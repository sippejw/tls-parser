//!
//! TLS extensions are defined in:
//!
//! - [RFC4492](https://tools.ietf.org/html/rfc4492)
//! - [RFC6066](https://tools.ietf.org/html/rfc6066)
//! - [RFC7366](https://tools.ietf.org/html/rfc7366)
//! - [RFC7627](https://tools.ietf.org/html/rfc7627)

use crate::tls::{parse_tls_versions, TlsCipherSuiteID, TlsVersion};
use crate::tls_ec::{parse_named_groups, NamedGroup};
use crate::tls_sign_hash::SignatureScheme;
use alloc::{vec, vec::Vec};
use core::convert::From;
use nom::bytes::streaming::{tag, take};
use nom::combinator::{complete, cond, map, map_parser, opt, verify};
// use nom::error::{make_error, ErrorKind};
use nom::multi::{length_data, many0};
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::IResult;
use nom_derive::{NomBE, Parse};
use rusticata_macros::newtype_enum;
use serde::Serialize;

/// TLS extension types,
/// defined in the [IANA Transport Layer Security (TLS)
/// Extensions](http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
/// registry
#[derive(Clone, Copy, Debug, PartialEq, Eq, NomBE, Hash, Serialize)]
pub struct TlsExtensionType(pub u16);

newtype_enum! {
impl display TlsExtensionType {
    ServerName                          = 0, // [RFC6066]
    MaxFragmentLength                   = 1,
    ClientCertificate                   = 2,
    TrustedCaKeys                       = 3,
    TruncatedHMac                       = 4,
    StatusRequest                       = 5, // [RFC6066]
    UserMapping                         = 6,
    ClientAuthz                         = 7,
    ServerAuthz                         = 8,
    CertType                            = 9,
    SupportedGroups                     = 10, // [RFC4492][RFC7919]
    EcPointFormats                      = 11, // [RFC4492]
    Srp                                 = 12, // [RFC5054]
    SignatureAlgorithms                 = 13, // [RFC8446]
    UseSrtp                             = 14,
    Heartbeat                           = 15, // [RFC6520]
    ApplicationLayerProtocolNegotiation = 16, // [RFC7301]
    StatusRequestv2                     = 17,
    SignedCertificateTimestamp          = 18,
    ClientCertificateType               = 19,
    ServerCertificateType               = 20,
    Padding                             = 21, // [RFC7685]
    EncryptThenMac                      = 22, // [RFC7366]
    ExtendedMasterSecret                = 23, // [RFC7627]
    TokenBinding                        = 24,
    CachedInfo                          = 25,
    CompressCertificate                 = 27, // [RFC8879]
    RecordSizeLimit                     = 28, // [RFC8449]
    PwdProtect                          = 29,
    PwdClear                            = 30,
    PasswordSalt                        = 31,
    TicketPinning                       = 32,
    TlsCertWithExternPsk                = 33,
    DelegatedCredentials                = 34,
    SessionTicketTLS                    = 35,
    Tlmsp                               = 36,
    TlmspProxying                       = 37,
    TlmspDelegate                       = 38,
    SupportedEktCiphers                 = 39,
    KeyShareOld                         = 40, // moved to 51 in TLS 1.3 draft 23
    PreSharedKey                        = 41, // [RFC8446]
    EarlyData                           = 42, // [RFC8446]
    SupportedVersions                   = 43, // [RFC8446]
    Cookie                              = 44, // [RFC8446]
    PskExchangeModes                    = 45, // [RFC8446]
    TicketEarlyDataInfo                 = 46, // TLS 1.3 draft 18, removed in draft 19
    CertificateAuthorities              = 47, // [RFC8446]
    OidFilters                          = 48, // [RFC8446]
    PostHandshakeAuth                   = 49, // [RFC8446]
    SigAlgorithmsCert                   = 50, // [RFC8446]
    KeyShare                            = 51, // [RFC8446]
    TransparencyInfo                    = 52, // [RFC8446]
    ConnectionIdOld                     = 53, // deprecated
    ConnectionId                        = 54,
    ExternalIdHash                      = 55, // [RFC8844]
    ExternalSessionId                   = 56, // [RFC8844]
    QuicTransportParameters             = 57, // [RFC9001]
    TicketRequest                       = 58,
    DnssecChain                         = 58,

    NextProtocolNegotiation             = 13172,

    Grease                              = 0xfafa,

    RenegotiationInfo                   = 0xff01, // [RFC5746]
    EncryptedClientHello                = 0xfe0d, // [draft-ietf-tls-esni]
    EncryptedServerName                 = 0xffce, // draft-ietf-tls-esni
}
}

impl TlsExtensionType {
    pub fn from_u16(t: u16) -> TlsExtensionType {
        TlsExtensionType(t)
    }
}

impl From<TlsExtensionType> for u16 {
    fn from(ext: TlsExtensionType) -> u16 {
        ext.0
    }
}

/// TLS extensions
///
#[derive(Clone, PartialEq, Hash, Serialize)]
pub enum TlsExtension<'a> {
    SNI(Vec<(SNIType, &'a [u8])>),
    MaxFragmentLength(u8),
    StatusRequest(Option<(CertificateStatusType, &'a [u8])>),
    SupportedGroups(Vec<NamedGroup>),
    EcPointFormats(&'a [u8]),
    SignatureAlgorithms(Vec<SignatureScheme>),
    CompressCertificate(&'a [u8]),
    RecordSizeLimit(u16),
    SessionTicket(&'a [u8]),
    KeyShareOld(&'a [u8]),
    KeyShare(Vec<KeyShareEntry<'a>>),
    PreSharedKey(&'a [u8]),
    EarlyData(Option<u32>),
    SupportedVersions(Vec<TlsVersion>),
    Cookie(&'a [u8]),
    PskExchangeModes(Vec<u8>),
    Heartbeat(u8),
    ALPN(Vec<&'a [u8]>),

    SignedCertificateTimestamp(Option<&'a [u8]>),
    Padding(&'a [u8]),
    EncryptThenMac,
    ExtendedMasterSecret,

    OidFilters(Vec<OidFilter<'a>>),
    PostHandshakeAuth,

    NextProtocolNegotiation,

    RenegotiationInfo(&'a [u8]),

    EncryptedClientHello {
        ch_type: u8,
        ciphersuite: u32,
        config_id: u8,
        enc: &'a [u8],
        payload: &'a [u8],
    },

    EncryptedServerName {
        ciphersuite: TlsCipherSuiteID,
        group: NamedGroup,
        key_share: &'a [u8],
        record_digest: &'a [u8],
        encrypted_sni: &'a [u8],
    },

    QuicTransportParameters(&'a [u8]),

    Grease(u16, &'a [u8]),

    Unknown(TlsExtensionType, &'a [u8]),
}

impl<'a> From<&'a TlsExtension<'a>> for TlsExtensionType {
    #[rustfmt::skip]
    fn from(ext: &TlsExtension) -> TlsExtensionType {
        match *ext {
            TlsExtension::SNI(_)                        => TlsExtensionType::ServerName,
            TlsExtension::MaxFragmentLength(_)          => TlsExtensionType::MaxFragmentLength,
            TlsExtension::StatusRequest(_)              => TlsExtensionType::StatusRequest,
            TlsExtension::SupportedGroups(_)             => TlsExtensionType::SupportedGroups,
            TlsExtension::EcPointFormats(_)             => TlsExtensionType::EcPointFormats,
            TlsExtension::SignatureAlgorithms(_)        => TlsExtensionType::SignatureAlgorithms,
            TlsExtension::CompressCertificate(_)        => TlsExtensionType::CompressCertificate,
            TlsExtension::SessionTicket(_)              => TlsExtensionType::SessionTicketTLS,
            TlsExtension::RecordSizeLimit(_)            => TlsExtensionType::RecordSizeLimit,
            TlsExtension::KeyShareOld(_)                => TlsExtensionType::KeyShareOld,
            TlsExtension::KeyShare(_)                   => TlsExtensionType::KeyShare,
            TlsExtension::PreSharedKey(_)               => TlsExtensionType::PreSharedKey,
            TlsExtension::EarlyData(_)                  => TlsExtensionType::EarlyData,
            TlsExtension::SupportedVersions(_)          => TlsExtensionType::SupportedVersions,
            TlsExtension::Cookie(_)                     => TlsExtensionType::Cookie,
            TlsExtension::PskExchangeModes(_)           => TlsExtensionType::PskExchangeModes,
            TlsExtension::Heartbeat(_)                  => TlsExtensionType::Heartbeat,
            TlsExtension::ALPN(_)                       => TlsExtensionType::ApplicationLayerProtocolNegotiation,
            TlsExtension::SignedCertificateTimestamp(_) => TlsExtensionType::SignedCertificateTimestamp,
            TlsExtension::Padding(_)                    => TlsExtensionType::Padding,
            TlsExtension::EncryptThenMac                => TlsExtensionType::EncryptThenMac,
            TlsExtension::ExtendedMasterSecret          => TlsExtensionType::ExtendedMasterSecret,
            TlsExtension::OidFilters(_)                 => TlsExtensionType::OidFilters,
            TlsExtension::PostHandshakeAuth             => TlsExtensionType::PostHandshakeAuth,
            TlsExtension::NextProtocolNegotiation       => TlsExtensionType::NextProtocolNegotiation,
            TlsExtension::RenegotiationInfo(_)          => TlsExtensionType::RenegotiationInfo,
            TlsExtension::EncryptedClientHello{..}     => TlsExtensionType::EncryptedClientHello,
            TlsExtension::EncryptedServerName{..}       => TlsExtensionType::EncryptedServerName,
            TlsExtension::QuicTransportParameters(_)    => TlsExtensionType::QuicTransportParameters,
            TlsExtension::Grease(_,_)                   => TlsExtensionType::Grease,
            TlsExtension::Unknown(x,_)                  => x
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, NomBE, Hash, Serialize)]
pub struct KeyShareEntry<'a> {
    pub group: NamedGroup, // NamedGroup
    #[nom(Parse = "length_data(be_u16)")]
    pub kx: &'a [u8], // Key Exchange Data
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, NomBE, Hash, Serialize)]
pub struct PskKeyExchangeMode(pub u8);

newtype_enum! {
impl PskKeyExchangeMode {
    Psk    = 0,
    PskDhe = 1,
}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, NomBE, Hash, Serialize)]
pub struct SNIType(pub u8);

newtype_enum! {
impl display SNIType {
    HostName = 0,
}
}

#[derive(Clone, Copy, PartialEq, Eq, NomBE, Hash, Serialize)]
pub struct CertificateStatusType(pub u8);

newtype_enum! {
impl debug CertificateStatusType {
    OCSP = 1,
}
}

#[derive(Clone, Debug, PartialEq, Hash, Serialize)]
pub struct OidFilter<'a> {
    pub cert_ext_oid: &'a [u8],
    pub cert_ext_val: &'a [u8],
}


#[derive(Clone, Debug, PartialEq, Hash, Serialize)]
pub struct QuicTransportParameter<'a>{
    pub id: u64,
    pub value: &'a [u8],
}

// struct {
//     NameType name_type;
//     select (name_type) {
//         case host_name: HostName;
//     } name;
// } ServerName;
//
// enum {
//     host_name(0), (255)
// } NameType;
//
// opaque HostName<1..2^16-1>;
pub fn parse_tls_extension_sni_hostname(i: &[u8]) -> IResult<&[u8], (SNIType, &[u8])> {
    let (i, t) = SNIType::parse(i)?;
    let (i, v) = length_data(be_u16)(i)?;
    Ok((i, (t, v)))
}

// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
pub fn parse_tls_extension_sni_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    if i.is_empty() {
        // special case: SNI extension in server can be empty
        return Ok((i, TlsExtension::SNI(Vec::new())));
    }
    let (i, list_len) = be_u16(i)?;
    let (i, v) = map_parser(
        take(list_len),
        many0(complete(parse_tls_extension_sni_hostname)),
    )(i)?;
    Ok((i, TlsExtension::SNI(v)))
}

pub fn parse_tls_extension_sni(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x00])(i)?;
    map_parser(length_data(be_u16), parse_tls_extension_sni_content)(i)
}

/// Max fragment length [RFC6066]
pub fn parse_tls_extension_max_fragment_length_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    map(be_u8, TlsExtension::MaxFragmentLength)(i)
}

/// Max fragment length [RFC6066]
pub fn parse_tls_extension_max_fragment_length(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x01])(i)?;
    map_parser(
        length_data(be_u16),
        parse_tls_extension_max_fragment_length_content,
    )(i)
}

/// Status Request [RFC6066]
fn parse_tls_extension_status_request_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    match ext_len {
        0 => Ok((i, TlsExtension::StatusRequest(None))),
        _ => {
            let (i, status_type) = be_u8(i)?;
            let (i, request) = take(ext_len - 1)(i)?;
            Ok((
                i,
                TlsExtension::StatusRequest(Some((CertificateStatusType(status_type), request))),
            ))
        }
    }
}

pub fn parse_tls_extension_status_request(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x05])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_status_request_content(d, ext_len)
    })(i)
}

// defined in rfc8422, rfc7919
// Renamed from "elliptic_curves"
pub fn parse_tls_extension_supported_groups_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    map_parser(
        length_data(be_u16),
        map(parse_named_groups, TlsExtension::SupportedGroups),
    )(i)
}

pub fn parse_tls_extension_supported_groups(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x0a])(i)?;
    map_parser(
        length_data(be_u16),
        parse_tls_extension_supported_groups_content,
    )(i)
}

pub fn parse_tls_extension_ec_point_formats_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    map(length_data(be_u8), TlsExtension::EcPointFormats)(i)
}

pub fn parse_tls_extension_ec_point_formats(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x0a])(i)?;
    map_parser(
        length_data(be_u16),
        parse_tls_extension_ec_point_formats_content,
    )(i)
}

/// Parse 'Signature Algorithms' extension (rfc8446, TLS 1.3 only, has backwards compatibility
/// with pre TLS 1.3 Signature Algorithms)
pub fn parse_tls_extension_signature_algorithms_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, l) = map_parser(length_data(be_u16), many0(complete(SignatureScheme::parse)))(i)?;
    Ok((i, TlsExtension::SignatureAlgorithms(l)))
}

pub fn parse_tls_extension_signature_algorithms(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 13])(i)?;
    map_parser(
        length_data(be_u16),
        parse_tls_extension_signature_algorithms_content,
    )(i)
}

// rfc6520
pub fn parse_tls_extension_heartbeat_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    map(be_u8, TlsExtension::Heartbeat)(i)
}

pub fn parse_tls_extension_heartbeat(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x0d])(i)?;
    let (i, ext_len) = verify(be_u16, |&n| n == 1)(i)?;
    map_parser(take(ext_len), parse_tls_extension_heartbeat_content)(i)
}

fn parse_protocol_name(i: &[u8]) -> IResult<&[u8], &[u8]> {
    length_data(be_u8)(i)
}

/// Defined in [RFC7301]
pub fn parse_tls_extension_alpn_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, v) = map_parser(length_data(be_u16), many0(complete(parse_protocol_name)))(i)?;
    Ok((i, TlsExtension::ALPN(v)))
}

/// Defined in [RFC7685]
fn parse_tls_extension_padding_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    map(take(ext_len), TlsExtension::Padding)(i)
}

/// Defined in [RFC6962]
pub fn parse_tls_extension_signed_certificate_timestamp_content(
    i: &[u8],
) -> IResult<&[u8], TlsExtension> {
    map(
        opt(complete(length_data(be_u16))),
        TlsExtension::SignedCertificateTimestamp,
    )(i)
}

/// Encrypt-then-MAC is defined in [RFC7366]
fn parse_tls_extension_encrypt_then_mac_content(
    i: &[u8],
    _ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    // if ext_len != 0 {
    //     return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    // }
    Ok((i, TlsExtension::EncryptThenMac))
}

/// Encrypt-then-MAC is defined in [RFC7366]
pub fn parse_tls_extension_encrypt_then_mac(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x16])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_encrypt_then_mac_content(d, ext_len)
    })(i)
}

/// Extended Master Secret is defined in [RFC7627]
fn parse_tls_extension_extended_master_secret_content(
    i: &[u8],
    _ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    // if ext_len != 0 {
    //     return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    // }
    Ok((i, TlsExtension::ExtendedMasterSecret))
}

/// Extended Master Secret is defined in [RFC7627]
pub fn parse_tls_extension_extended_master_secret(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x17])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_extended_master_secret_content(d, ext_len)
    })(i)
}

/// Extended Record Size Limit is defined in [RFC7627]
fn parse_tls_extension_record_size_limit(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    map(be_u16, TlsExtension::RecordSizeLimit)(i)
}

fn parse_tls_extension_session_ticket_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    map(take(ext_len), TlsExtension::SessionTicket)(i)
}

pub fn parse_tls_extension_session_ticket(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x23])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_session_ticket_content(d, ext_len)
    })(i)
}

fn parse_tls_extension_key_share_old_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    map(take(ext_len), TlsExtension::KeyShareOld)(i)
}

fn parse_keyshare_entry(i: &[u8]) -> IResult<&[u8], KeyShareEntry> {
    KeyShareEntry::parse(i)
}

/// Key Share content depends on the current message type
fn parse_tls_extension_client_shares_content(
    i: &[u8],
    _ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    let (i, v) = map_parser(length_data(be_u16), many0(complete(parse_keyshare_entry)))(i)?;
    Ok((i, TlsExtension::KeyShare(v)))
}

/// Key Share content depends on the current message type
fn parse_tls_extension_server_share_content(
    i: &[u8],
    _ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    let (i, t) = parse_keyshare_entry(i)?;
    //let (i, t) = map_parser(take(ext_len), parse_keyshare_entry)(i)?;
    Ok((i, TlsExtension::KeyShare(vec![t])))
}

/// Return a TlsExtension::KeyShareOld with just the bytes
pub fn parse_tls_extension_key_share(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x33])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_key_share_old_content(d, ext_len)
    })(i)
}

fn parse_tls_extension_pre_shared_key_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    map(take(ext_len), TlsExtension::PreSharedKey)(i)
}

pub fn parse_tls_extension_pre_shared_key(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x28])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_pre_shared_key_content(d, ext_len)
    })(i)
}

fn parse_tls_extension_compress_certificate_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    map(take(ext_len), TlsExtension::CompressCertificate)(i)
}

pub fn parse_tls_extension_compress_certificate(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x1b])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_compress_certificate_content(d, ext_len)
    })(i)
}

fn parse_tls_extension_early_data_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    map(cond(ext_len > 0, be_u32), TlsExtension::EarlyData)(i)
}

pub fn parse_tls_extension_early_data(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x2a])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_early_data_content(d, ext_len)
    })(i)
}

// TLS 1.3 draft 23
//       struct {
//           select (Handshake.msg_type) {
//               case client_hello:
//                    ProtocolVersion versions<2..254>;
//
//               case server_hello: /* and HelloRetryRequest */
//                    ProtocolVersion selected_version;
//           };
//       } SupportedVersions;
// XXX the content depends on the current message type
// XXX first case has length 1 + 2*n, while the second case has length 2
fn parse_tls_extension_supported_versions_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    if ext_len == 2 {
        map(be_u16, |x| {
            TlsExtension::SupportedVersions(vec![TlsVersion(x)])
        })(i)
    } else {
        let (i, _) = be_u8(i)?;
        // if ext_len == 0 {
        //     return Err(Err::Error(make_error(i, ErrorKind::Verify)));
        // }
        let (i, l) = map_parser(take(ext_len - 1), parse_tls_versions)(i)?;
        Ok((i, TlsExtension::SupportedVersions(l)))
    }
}

pub fn parse_tls_extension_supported_versions(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x2b])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_supported_versions_content(d, ext_len)
    })(i)
}

fn parse_tls_extension_cookie_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    map(take(ext_len), TlsExtension::Cookie)(i)
}

pub fn parse_tls_extension_cookie(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x2c])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(take(ext_len), move |d| {
        parse_tls_extension_cookie_content(d, ext_len)
    })(i)
}

pub fn parse_tls_extension_psk_key_exchange_modes_content(
    i: &[u8],
) -> IResult<&[u8], TlsExtension> {
    let (i, v) = length_data(be_u8)(i)?;
    Ok((i, TlsExtension::PskExchangeModes(v.to_vec())))
}

pub fn parse_tls_extension_psk_key_exchange_modes(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, _) = tag([0x00, 0x2d])(i)?;
    let (i, ext_len) = be_u16(i)?;
    map_parser(
        take(ext_len),
        parse_tls_extension_psk_key_exchange_modes_content,
    )(i)
}

/// Defined in RFC-draft-agl-tls-nextprotoneg-03. Deprecated in favour of ALPN.
fn parse_tls_extension_npn_content(i: &[u8], _ext_len: u16) -> IResult<&[u8], TlsExtension> {
    // if ext_len != 0 {
    //     return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    // }
    Ok((i, TlsExtension::NextProtocolNegotiation))
}

/// Renegotiation Info, defined in [RFC5746]
pub fn parse_tls_extension_renegotiation_info_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    map(length_data(be_u8), TlsExtension::RenegotiationInfo)(i)
}

// Encrypted Client Hello, defined in [draft-ietf-tls-esni]
pub fn parse_tls_extension_encrypted_client_hello(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, ch_type) = be_u8(i)?;
    let (i, ciphersuite) = be_u32(i)?;
    let (i, config_id) = be_u8(i)?;
    let (i, enc) = length_data(be_u16)(i)?;
    let (i, payload) = length_data(be_u16)(i)?;
    let ech = TlsExtension::EncryptedClientHello {
        ch_type,
        ciphersuite,
        config_id,
        enc,
        payload,
    };
    Ok((i, ech))
}

/// Encrypted Server Name, defined in [draft-ietf-tls-esni]
pub fn parse_tls_extension_encrypted_server_name(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, ciphersuite) = map(be_u16, TlsCipherSuiteID)(i)?;
    let (i, group) = NamedGroup::parse(i)?;
    let (i, key_share) = length_data(be_u16)(i)?;
    let (i, record_digest) = length_data(be_u16)(i)?;
    let (i, encrypted_sni) = length_data(be_u16)(i)?;
    let esn = TlsExtension::EncryptedServerName {
        ciphersuite,
        group,
        key_share,
        record_digest,
        encrypted_sni,
    };
    Ok((i, esn))
}

fn parse_tls_oid_filter(i: &[u8]) -> IResult<&[u8], OidFilter> {
    let (i, cert_ext_oid) = length_data(be_u8)(i)?;
    let (i, cert_ext_val) = length_data(be_u16)(i)?;
    let filter = OidFilter {
        cert_ext_oid,
        cert_ext_val,
    };
    Ok((i, filter))
}

/// Defined in TLS 1.3 draft 19
fn parse_tls_extension_oid_filters(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, v) = map_parser(length_data(be_u16), many0(complete(parse_tls_oid_filter)))(i)?;
    Ok((i, TlsExtension::OidFilters(v)))
}

/// Defined in TLS 1.3 draft 20
fn parse_tls_extension_post_handshake_auth_content(
    i: &[u8],
    _ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    // if ext_len != 0 {
    //     return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    // }
    Ok((i, TlsExtension::PostHandshakeAuth))
}

/// QUIC Transport Parameters as defined in QUIC TLS [RFC9001]
fn parse_tls_extension_quic_transport_parameters(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    map(take(ext_len), TlsExtension::QuicTransportParameters)(i)
}

pub fn parse_tls_extension_unknown(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, ext_type) = be_u16(i)?;
    let (i, ext_data) = length_data(be_u16)(i)?;
    Ok((
        i,
        TlsExtension::Unknown(TlsExtensionType(ext_type), ext_data),
    ))
}

/// Parse a single TLS Client Hello extension
pub fn parse_tls_client_hello_extension(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, ext_type) = be_u16(i)?;
    let (i, ext_data) = length_data(be_u16)(i)?;
    if ext_type & 0x0f0f == 0x0a0a {
        return Ok((i, TlsExtension::Grease(ext_type, ext_data)));
    }
    let ext_len = ext_data.len() as u16;
    let (_, ext) = match ext_type {
        0 => parse_tls_extension_sni_content(ext_data),
        1 => parse_tls_extension_max_fragment_length_content(ext_data),
        5 => parse_tls_extension_status_request_content(ext_data, ext_len),
        10 => parse_tls_extension_supported_groups_content(ext_data),
        11 => parse_tls_extension_ec_point_formats_content(ext_data),
        13 => parse_tls_extension_signature_algorithms_content(ext_data),
        15 => parse_tls_extension_heartbeat_content(ext_data),
        16 => parse_tls_extension_alpn_content(ext_data),
        18 => parse_tls_extension_signed_certificate_timestamp_content(ext_data), // ok XXX should be empty
        21 => parse_tls_extension_padding_content(ext_data, ext_len),
        22 => parse_tls_extension_encrypt_then_mac_content(ext_data, ext_len),
        23 => parse_tls_extension_extended_master_secret_content(ext_data, ext_len),
        27 => parse_tls_extension_compress_certificate_content(ext_data, ext_len),
        28 => parse_tls_extension_record_size_limit(ext_data),
        35 => parse_tls_extension_session_ticket_content(ext_data, ext_len),
        41 => parse_tls_extension_pre_shared_key_content(ext_data, ext_len),
        42 => parse_tls_extension_early_data_content(ext_data, ext_len),
        43 => parse_tls_extension_supported_versions_content(ext_data, ext_len),
        44 => parse_tls_extension_cookie_content(ext_data, ext_len),
        45 => parse_tls_extension_psk_key_exchange_modes_content(ext_data),
        48 => parse_tls_extension_oid_filters(ext_data),
        49 => parse_tls_extension_post_handshake_auth_content(ext_data, ext_len),
        51 => parse_tls_extension_client_shares_content(ext_data, ext_len),
        57 => parse_tls_extension_quic_transport_parameters(ext_data, ext_len),
        13172 => parse_tls_extension_npn_content(ext_data, ext_len), // XXX must be empty
        0xff01 => parse_tls_extension_renegotiation_info_content(ext_data),
        0xfe0d => parse_tls_extension_encrypted_client_hello(ext_data),
        0xffce => parse_tls_extension_encrypted_server_name(ext_data),
        _ => Ok((
            i,
            TlsExtension::Unknown(TlsExtensionType(ext_type), ext_data),
        )),
    }?;
    Ok((i, ext))
}

/// Parse a single TLS Server Hello extension
pub fn parse_tls_server_hello_extension(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, ext_type) = be_u16(i)?;
    let (i, ext_data) = length_data(be_u16)(i)?;
    if ext_type & 0x0f0f == 0x0a0a {
        return Ok((i, TlsExtension::Grease(ext_type, ext_data)));
    }
    let ext_len = ext_data.len() as u16;
    let (_, ext) = match ext_type {
        0 => parse_tls_extension_sni_content(ext_data), // XXX SHALL be empty (RFC6066 section 3)
        1 => parse_tls_extension_max_fragment_length_content(ext_data),
        5 => parse_tls_extension_status_request_content(ext_data, ext_len), // SHALL be empty
        11 => parse_tls_extension_ec_point_formats_content(ext_data),       // ok XXX only one
        13 => parse_tls_extension_signature_algorithms_content(ext_data),   // XXX allowed?
        15 => parse_tls_extension_heartbeat_content(ext_data),
        16 => parse_tls_extension_alpn_content(ext_data), // ok XXX MUST contain one protocol name
        18 => parse_tls_extension_signed_certificate_timestamp_content(ext_data),
        21 => parse_tls_extension_encrypt_then_mac_content(ext_data, ext_len),
        23 => parse_tls_extension_extended_master_secret_content(ext_data, ext_len),
        27 => parse_tls_extension_compress_certificate_content(ext_data, ext_len),
        28 => parse_tls_extension_record_size_limit(ext_data),
        35 => parse_tls_extension_session_ticket_content(ext_data, ext_len),
        41 => parse_tls_extension_pre_shared_key_content(ext_data, ext_len),
        42 => parse_tls_extension_early_data_content(ext_data, ext_len),
        43 => parse_tls_extension_supported_versions_content(ext_data, ext_len), // ok XXX only one
        44 => parse_tls_extension_cookie_content(ext_data, ext_len),
        51 => parse_tls_extension_server_share_content(ext_data, ext_len),
        13172 => parse_tls_extension_npn_content(ext_data, ext_len),
        0xff01 => parse_tls_extension_renegotiation_info_content(ext_data),
        _ => Ok((
            i,
            TlsExtension::Unknown(TlsExtensionType(ext_type), ext_data),
        )),
    }?;
    Ok((i, ext))
}

/// Parse a single TLS extension (of any type)
pub fn parse_tls_extension(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    let (i, ext_type) = be_u16(i)?;
    let (i, ext_data) = length_data(be_u16)(i)?;
    if ext_type & 0x0f0f == 0x0a0a {
        return Ok((i, TlsExtension::Grease(ext_type, ext_data)));
    }
    let ext_len = ext_data.len() as u16;
    let (_, ext) = match ext_type {
        0 => parse_tls_extension_sni_content(ext_data),
        1 => parse_tls_extension_max_fragment_length_content(ext_data),
        5 => parse_tls_extension_status_request_content(ext_data, ext_len),
        10 => parse_tls_extension_supported_groups_content(ext_data),
        11 => parse_tls_extension_ec_point_formats_content(ext_data),
        13 => parse_tls_extension_signature_algorithms_content(ext_data),
        15 => parse_tls_extension_heartbeat_content(ext_data),
        16 => parse_tls_extension_alpn_content(ext_data),
        18 => parse_tls_extension_signed_certificate_timestamp_content(ext_data),
        21 => parse_tls_extension_padding_content(ext_data, ext_len),
        22 => parse_tls_extension_encrypt_then_mac_content(ext_data, ext_len),
        23 => parse_tls_extension_extended_master_secret_content(ext_data, ext_len),
        27 => parse_tls_extension_compress_certificate_content(ext_data, ext_len),
        28 => parse_tls_extension_record_size_limit(ext_data),
        35 => parse_tls_extension_session_ticket_content(ext_data, ext_len),
        40 => parse_tls_extension_key_share_old_content(ext_data, ext_len),
        41 => parse_tls_extension_pre_shared_key_content(ext_data, ext_len),
        42 => parse_tls_extension_early_data_content(ext_data, ext_len),
        43 => parse_tls_extension_supported_versions_content(ext_data, ext_len),
        44 => parse_tls_extension_cookie_content(ext_data, ext_len),
        45 => parse_tls_extension_psk_key_exchange_modes_content(ext_data),
        48 => parse_tls_extension_oid_filters(ext_data),
        49 => parse_tls_extension_post_handshake_auth_content(ext_data, ext_len),
        51 => parse_tls_extension_key_share_old_content(ext_data, ext_len),
        13172 => parse_tls_extension_npn_content(ext_data, ext_len),
        0xff01 => parse_tls_extension_renegotiation_info_content(ext_data),
        0xffce => parse_tls_extension_encrypted_server_name(ext_data),
        _ => Ok((
            i,
            TlsExtension::Unknown(TlsExtensionType(ext_type), ext_data),
        )),
    }?;
    Ok((i, ext))
}

/// Parse zero or more TLS Client Hello extensions
pub fn parse_tls_client_hello_extensions(i: &[u8]) -> IResult<&[u8], Vec<TlsExtension>> {
    many0(complete(parse_tls_client_hello_extension))(i)
}

/// Parse zero or more TLS Server Hello extensions
pub fn parse_tls_server_hello_extensions(i: &[u8]) -> IResult<&[u8], Vec<TlsExtension>> {
    many0(complete(parse_tls_server_hello_extension))(i)
}

/// Parse zero or more TLS extensions (of any type)
pub fn parse_tls_extensions(i: &[u8]) -> IResult<&[u8], Vec<TlsExtension>> {
    many0(complete(parse_tls_extension))(i)
}
