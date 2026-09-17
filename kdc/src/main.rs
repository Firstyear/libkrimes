#![deny(warnings)]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

mod cldap;
mod config;

use clap::{Parser, Subcommand};
use config::{Config, CoreAction, ServerState, TaskName};
use futures::{SinkExt, StreamExt};
use libkrimes::error::KrbError;
use libkrimes::proto::{
    AuthenticationRequest, AuthenticationTimeBound, DerivedKey, KdcPrimaryKey, KerberosReply,
    KerberosRequest, Name, TicketGrantRequest, TicketGrantRequestUnverified, TicketGrantTimeBound,
    TicketRenewTimeBound,
};
use libkrimes::KdcTcpCodec;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, instrument, trace};

#[instrument(level = "info", skip_all)]
#[allow(clippy::result_large_err)]
async fn process_authentication(
    auth_req: &AuthenticationRequest,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let stime = SystemTime::now();

    // Got any etypes?
    if auth_req.etypes.is_empty() {
        return Err(KerberosReply::error_no_etypes(
            auth_req.service_name.clone(),
            stime,
        ));
    }

    // The service name must be krbtgt for this realm.
    if !auth_req
        .service_name
        .is_service_krbtgt(server_state.realm.as_str())
    {
        error!("Request not for KRBTGT ({:?})", auth_req.service_name);
        return Err(KerberosReply::error_as_not_krbtgt(
            auth_req.service_name.clone(),
            stime,
        ));
    }

    // Is the client for our realm?
    // Is the client in our user db?
    // This look up answer both as the client_name contains realm given how we structure
    // the name enum
    let Some(principal_record) = server_state.principals.get(&auth_req.client_name) else {
        return Err(KerberosReply::error_client_username(
            auth_req.service_name.clone(),
            stime,
        ));
    };

    // Now, if the req is a user princ or a service princ we have to take different paths.
    // This is because user princs demand pre-auth, but service ones don't. Service princs
    // are required to have stronger keys which is why they are exempted.

    if !principal_record.service {
        let Some(pre_enc_timestamp) = auth_req.preauth.enc_timestamp() else {
            info!("ENC-TS Preauth not present, returning pre-auth parameters.");
            let parep = KerberosReply::preauth_builder(auth_req.service_name.clone(), stime)
                // This sets the correct number of iterations based on what the principals
                // key is set to use. We generally bump this value up because the defaults
                // are woefully inadequate.
                .set_key_params(&principal_record.base_key)
                .build();

            trace!(?parep);

            // Request pre-auth.
            return Ok(parep);
        };
        info!("ENC-TS Preauth present.");

        // Start to process and validate the enc timestamp.

        let pa_timestamp = pre_enc_timestamp
            .decrypt_pa_enc_timestamp(&principal_record.base_key)
            .map_err(|err| {
                error!(?err, "pre_enc_timestamp.decrypt");
                KerberosReply::error_preauth_failed(auth_req.service_name.clone(), stime)
            })?;

        trace!(?pa_timestamp, ?stime);

        let abs_offset = if pa_timestamp > stime {
            pa_timestamp.duration_since(stime)
        } else {
            stime.duration_since(pa_timestamp)
        }
        // This error shouldn't be possible. The error condition on duration_since is
        // when the right side of the term is actually *before* the left. Our if
        // condition should guard against thin.
        // However, let's do the right thing and check it anyway.
        .map_err(|kdc_err| {
            error!(?kdc_err);
            KerberosReply::error_internal(auth_req.service_name.clone(), stime)
        })?;

        trace!(?abs_offset);

        // Check for the timestamp being in a valid range. If not, reject for clock skew.
        if abs_offset > server_state.allowed_clock_skew {
            error!(?abs_offset, "clock skew");
            // ClockSkew
            return Err(KerberosReply::error_clock_skew(
                auth_req.service_name.clone(),
                stime,
            ));
        }

        // Preauthentication SUCCESS. Now we can consider issuing a ticket.

        trace!("PREAUTH SUCCESS");
    }

    // This function will perform safe calculations of the time bounds.
    let time_bounds = match AuthenticationTimeBound::from_as_req(
        stime,
        server_state.allowed_clock_skew,
        server_state.ticket_min_lifetime,
        server_state.ticket_granting_ticket_lifetime,
        server_state.ticket_granting_ticket_lifetime,
        server_state.ticket_max_renew_time,
        auth_req,
    ) {
        Ok(time_bounds) => time_bounds,
        Err(time_bound_error) => {
            return Err(time_bound_error.to_kerberos_reply(&auth_req.service_name, stime))
        }
    };

    /*
     * The flags field of the new ticket will have the following options set
     * if they have been requested and if the policy of the local realm
     * allows:  FORWARDABLE, MAY-POSTDATE, POSTDATED, PROXIABLE, RENEWABLE.
     * If the new ticket is postdated (the starttime is in the future), its
     * INVALID flag will also be set.
     */

    // We should not bother with forwarded/proxiable until there is a genuine
    // need for them. If anything we should never add them as these are insecure
    // options.

    let builder = KerberosReply::authentication_builder(
        auth_req.client_name.clone(),
        Name::service_krbtgt(server_state.realm.as_str()),
        time_bounds,
        auth_req.nonce,
    );

    builder
        .build(&principal_record.base_key, &server_state.primary_key)
        .map_err(|kdc_err| {
            error!(?kdc_err);
            KerberosReply::error_internal(auth_req.service_name.clone(), stime)
        })
}

#[instrument(level = "info", skip_all)]
#[allow(clippy::result_large_err)]
async fn process_ticket_grant(
    tgs_req: &TicketGrantRequestUnverified,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    let stime = SystemTime::now();

    let tgs_req_valid = tgs_req
        .validate(&server_state.primary_key, &server_state.realm)
        .map_err(|err| {
            error!(?err, "Unable to validate tgs_req");
            let service_name = Name::service_krbtgt(server_state.realm.as_str());
            match err {
                KrbError::UnsupportedChecksumType => {
                    KerberosReply::error_unsupported_checksum(service_name, stime)
                }
                KrbError::ApInappChecksum => {
                    KerberosReply::error_inappropiate_checksum(service_name, stime)
                }
                _ => KerberosReply::error_request_failed_validation(service_name, stime),
            }
        })?;

    trace!(?tgs_req_valid);

    let service_name = tgs_req_valid.service_name().clone().service_hst_normalise();

    trace!(?service_name);

    // TODO If renew flag set
    // TODO This option (renew) will only be honored if the ticket to be renewed has its RENEWABLE flag set and if the time in its renew-till field has not passed.
    if service_name.is_service_krbtgt(server_state.realm.as_str()) {
        // This is a renewal request for the users TGT
        return process_ticket_renewal(tgs_req_valid, server_state).await;
    }

    // TODO!!!!!
    // =========
    // At this point we should also be verifying the requesting principals session
    // validity.

    // Is the service in our db?
    let Some(service_record) = server_state.principals.get(&service_name) else {
        error!(?service_name, "Unable to find service name");
        return Err(KerberosReply::error_service_name(service_name, stime));
    };

    let time_bounds = match TicketGrantTimeBound::from_tgs_req(
        stime,
        server_state.allowed_clock_skew,
        server_state.service_granting_ticket_lifetime,
        &tgs_req_valid,
    ) {
        Ok(time_bounds) => time_bounds,
        Err(time_bound_error) => {
            return Err(time_bound_error.to_kerberos_reply(&service_name, stime))
        }
    };

    let builder = KerberosReply::ticket_grant_builder(tgs_req_valid, time_bounds);

    builder.build(&service_record.base_key).map_err(|kdc_err| {
        error!(?kdc_err);
        KerberosReply::error_internal(service_name, stime)
    })
}

#[instrument(level = "info", skip_all)]
#[allow(clippy::result_large_err)]
async fn process_ticket_renewal(
    tgs_req_valid: TicketGrantRequest,
    server_state: &ServerState,
) -> Result<KerberosReply, KerberosReply> {
    // The KDC will issue a new ticket with a new session key and a later expiration time.  All other fields of the ticket are left unmodified by the renewal process.
    let stime = SystemTime::now();
    let service_name = tgs_req_valid.service_name().clone();

    let time_bounds = match TicketRenewTimeBound::from_tgs_req(
        stime,
        server_state.allowed_clock_skew,
        server_state.ticket_granting_ticket_lifetime,
        &tgs_req_valid,
    ) {
        Ok(time_bounds) => time_bounds,
        Err(time_bound_error) => {
            return Err(time_bound_error.to_kerberos_reply(&service_name, stime))
        }
    };

    let builder = KerberosReply::ticket_renew_builder(tgs_req_valid, time_bounds);

    builder.build(&server_state.primary_key).map_err(|kdc_err| {
        error!(?kdc_err);
        KerberosReply::error_internal(service_name, stime)
    })
}

async fn kdc_tcp_client_process(
    tcpstream: TcpStream,
    client_address: SocketAddr,
    server_state: Arc<ServerState>,
) {
    let mut kdc_stream = Framed::new(tcpstream, KdcTcpCodec::default());
    trace!(?client_address, "connection from");

    while let Some(Ok(kdc_req)) = kdc_stream.next().await {
        trace!(?kdc_req);
        match kdc_req {
            KerberosRequest::AS(auth_req) => {
                let reply = match process_authentication(&auth_req, &server_state).await {
                    Ok(rep) => rep,
                    Err(krb_err) => krb_err,
                };

                if let Err(err) = kdc_stream.send(reply).await {
                    error!(?err, "error writing response, disconnecting");
                    break;
                }
                continue;
            }
            KerberosRequest::TGS(tgs_req) => {
                let reply = match process_ticket_grant(&tgs_req, &server_state).await {
                    Ok(rep) => rep,
                    Err(krb_err) => krb_err,
                };

                if let Err(err) = kdc_stream.send(reply).await {
                    error!(?err, "error writing response, disconnecting");
                    break;
                }
                continue;
            }
        }
    }
    debug!("closing client");
}

#[derive(Debug, clap::Parser)]
#[clap(about = "The Worlds Worst KDC - A Krime, If You Please")]
struct OptParser {
    // Apparently globals can't be required?
    // #[clap(global = true)]
    // config: PathBuf,
    #[clap(subcommand)]
    command: Opt,
}

#[derive(Debug, Subcommand)]
#[clap(about = "The Worlds Worst KDC - A Krime, If You Please")]
enum Opt {
    Run {
        config: PathBuf,
    },
    Keytab {
        config: PathBuf,
        name: String,
        output: PathBuf,
    },
}

async fn kdc_tcp_acceptor(
    listener: TcpListener,
    server_state: Arc<ServerState>,
    mut rx: broadcast::Receiver<CoreAction>,
) {
    info!("Started task {}", TaskName::KdcTcp);

    loop {
        tokio::select! {
        Ok(action) = rx.recv() => {
            match action {
                CoreAction::Shutdown => break,
            }
        }
        accept_result = listener.accept() => {
               match accept_result {
                    Ok((tcpstream, client_socket_addr)) => {
                        let state = server_state.clone();
                        tokio::spawn(async move {kdc_tcp_client_process(tcpstream, client_socket_addr, state).await });
                    },
                    Err(e) => {
                        error!("LDAP acceptor error, continuing -> {:?}", e);
                    }
                }
            }
        }
    }

    info!("Stopped task {}", TaskName::KdcTcp);
}

async fn create_kdc_tcp_server(
    address: &str,
    server_state: Arc<ServerState>,
    rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let addr = SocketAddr::from_str(address).map_err(|e| {
        error!("Could not parse KDC server address {} -> {:?}", address, e);
    })?;

    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        error!(
            "Could not bind to KDC server address {} -> {:?}",
            address, e
        );
    })?;

    let kdc_tcp_handle = tokio::spawn(kdc_tcp_acceptor(listener, server_state, rx));

    Ok(kdc_tcp_handle)
}

struct CoreHandle {
    clean_shutdown: bool,
    tx: broadcast::Sender<CoreAction>,
    handles: Vec<(TaskName, tokio::task::JoinHandle<()>)>,
}

impl CoreHandle {
    async fn shutdown(&mut self) {
        if self.tx.send(CoreAction::Shutdown).is_err() {
            eprintln!("No receivers acked shutdown request. Treating as unclean.");
            return;
        }

        // Wait on the handles.
        while let Some((handle_name, handle)) = self.handles.pop() {
            if let Err(error) = handle.await {
                eprintln!("Task {handle_name} failed to finish: {error:?}");
            }
        }

        self.clean_shutdown = true;
    }
}

impl Drop for CoreHandle {
    fn drop(&mut self) {
        if !self.clean_shutdown {
            eprintln!("⚠️  UNCLEAN SHUTDOWN OCCURRED ⚠️ ");
        }
        debug_assert!(self.clean_shutdown);
    }
}

async fn create_server_core(config: &Config) -> Result<CoreHandle, ()> {
    let (broadcast_tx, mut _broadcast_rx) = broadcast::channel(4);

    let server_state = ServerState::try_from(config).map(Arc::new).map_err(|e| {
        error!("Could not get server state from config -> {:?}", e);
    })?;

    let mut handles: Vec<(TaskName, tokio::task::JoinHandle<()>)> = vec![];

    let kdc_handle = create_kdc_tcp_server(
        &config.address,
        server_state.clone(),
        broadcast_tx.subscribe(),
    )
    .await?;
    handles.push((TaskName::KdcTcp, kdc_handle));

    if let Some(cldap_handle) = match &config.cldap {
        Some(cfg) => {
            let h = cldap::create_cldap_server(cfg, broadcast_tx.subscribe()).await?;
            Some(h)
        }
        None => {
            debug!("CLDAP server disabled");
            None
        }
    } {
        handles.push((TaskName::CldapUdp, cldap_handle));
    }

    Ok(CoreHandle {
        clean_shutdown: false,
        tx: broadcast_tx,
        handles,
    })
}

fn keytab_extract_run(name: &str, output: &Path, config: &Config) -> io::Result<()> {
    use libkrimes::keytab::{Keytab, KeytabEntry};

    let server_state = ServerState::try_from(config)
        .map(Arc::new)
        .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "data"))?;

    let principal_name = if let Some((srv, host)) = name.split_once('/') {
        Name::service(srv, host, server_state.realm.as_str())
    } else {
        Name::principal(name, server_state.realm.as_str())
    };

    let key: DerivedKey = if principal_name.is_service_krbtgt(&server_state.realm) {
        let (k, kvno) = match server_state.primary_key {
            KdcPrimaryKey::Aes256 { ref k, kvno } => (k.clone(), kvno),
        };

        DerivedKey::Aes256CtsHmacSha196 {
            k,
            i: 0,
            s: String::new(),
            kvno,
        }
    } else {
        let principal_record = server_state
            .principals
            .get(&principal_name)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "no matching principal")
            })?;
        principal_record.base_key.clone()
    };

    let entry = KeytabEntry {
        principal: principal_name,
        timestamp: 0,
        key,
    };

    let ktname = "FILE:".to_owned() + output.to_string_lossy().to_string().as_str();
    let k: Keytab = if output.exists() {
        let mut keytab = libkrimes::keytab::load(Some(&ktname)).map_err(|err| {
            error!(?err, "Failed to load keytab file at {}", ktname);
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "keytab")
        })?;
        keytab.push(entry);
        keytab
    } else {
        vec![entry]
    };

    libkrimes::keytab::store(Some(&ktname), &k)
        .map_err(|_err| std::io::Error::new(std::io::ErrorKind::InvalidInput, "write"))?;

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), ()> {
    tracing_subscriber::fmt::init();

    let opt = OptParser::parse();

    match opt.command {
        Opt::Run { config } => {
            let cfg = Config::parse(&config).map_err(|e| {
                error!("Could not parse config file {:?}: {:?}", config, e);
            })?;

            let sctx = create_server_core(&cfg).await;
            match sctx {
                Ok(mut sctx) => {
                    loop {
                        let mut listener = sctx.tx.subscribe();
                        tokio::select! {
                            Ok(()) = tokio::signal::ctrl_c() => {
                                break
                            }
                            Some(()) = async move {
                                let sigterm = tokio::signal::unix::SignalKind::alarm();
                                #[allow(clippy::unwrap_used)]
                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                            } => {
                                // Ignore
                            }
                            Some(()) = async move {
                                let sigterm = tokio::signal::unix::SignalKind::hangup();
                                #[allow(clippy::unwrap_used)]
                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                            } => {
                                // Ignore
                            }
                            Some(()) = async move {
                                let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                                #[allow(clippy::unwrap_used)]
                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                            } => {
                                // Ignore
                            }
                            Some(()) = async move {
                                let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                                #[allow(clippy::unwrap_used)]
                                tokio::signal::unix::signal(sigterm).unwrap().recv().await
                            } => {
                                // Ignore
                            }
                            // we got a message on thr broadcast from somewhere else
                            Ok(msg) = async move {
                                listener.recv().await
                            } => {
                                debug!("Main loop received message: {:?}", msg);
                                break
                            }
                        }
                    }
                    info!("Signal received, shutting down");
                    // Send a broadcast that we are done.
                    sctx.shutdown().await;
                }
                Err(_) => {
                    error!("Failed to start server core!");
                    return Err(());
                }
            }
        }
        Opt::Keytab {
            name,
            output,
            config,
        } => {
            let cfg = Config::parse(&config).map_err(|e| {
                error!("Could not parse config file {:?}: {:?}", config, e);
            })?;
            keytab_extract_run(&name, &output, &cfg).map_err(|e| {
                error!(
                    "Could not extract principal {:?} to keytab {:?}: {:?}",
                    name, output, e
                );
            })?
        }
    }

    Ok(())
}
