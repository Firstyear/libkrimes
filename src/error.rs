#[derive(Debug, Clone)]
pub enum KrbError {
    InvalidHmacSha1Key,
    MessageAuthenticationFailed,
    MessageEmpty,
    InsufficientData,
    PlaintextEmpty,
    CtsCiphertextInvalid,
    UnsupportedEncryption,
    MissingPaData,
    DerDecodePaData,
    DerDecodeEtypeInfo2,
    DerEncodePaEncTsEnc,
    PreAuthUnsupported,
    PreAuthMissingEtypeInfo2,
    PreAuthInvalidUnixTs,
    PreAuthInvalidS2KParams,

    InvalidMessageType,
    InvalidMessageDirection,
    InvalidPvno,
    InvalidEnumValue(String, i32),
}
