//! Windows' WebAuthn API (spec v3 §8), the security-key build's only way to
//! a security key. webauthn.dll is loaded at run time from System32, and
//! only when a key file has keys or the user starts using keys; it is never
//! imported. The structs are webauthn.h's (SDK 10.0.26100.0, x64), held by
//! `const` assertions to the layout docs/webauthn-layout.txt records. The
//! request builders are pure functions; the answers are read only up to
//! their own `dwVersion`, every buffer of them that Windows owns and that
//! may hold the key's answer is wiped before Windows frees it, and Windows'
//! codes become the app's texts (its own text is never shown).
#![allow(non_snake_case)]
use goyo_vault::fido::{
    self, AssertRequest, Authenticator, CancelToken, FidoError, MakeRequest, RawAssertion,
    RawCredential,
};
use std::{
    ffi::{CStr, c_void},
    mem::{offset_of, size_of},
    ptr::{addr_of, null, null_mut},
    sync::{Arc, OnceLock},
};
use zeroize::Zeroizing;

type Pcwstr = *const u16;
type Bool = i32;
type Hresult = i32;
type Hwnd = isize;

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}
impl Guid {
    /// A cancel token's 16 bytes, as the GUID lies in memory.
    pub fn of(bytes: &[u8; 16]) -> Self {
        Self {
            d1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            d2: u16::from_le_bytes([bytes[4], bytes[5]]),
            d3: u16::from_le_bytes([bytes[6], bytes[7]]),
            d4: [
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ],
        }
    }
    fn bytes(&self) -> [u8; 16] {
        let mut out = [0; 16];
        out[..4].copy_from_slice(&self.d1.to_le_bytes());
        out[4..6].copy_from_slice(&self.d2.to_le_bytes());
        out[6..8].copy_from_slice(&self.d3.to_le_bytes());
        out[8..].copy_from_slice(&self.d4);
        out
    }
}
#[repr(C)]
struct RpEntity {
    dwVersion: u32,
    pwszId: Pcwstr,
    pwszName: Pcwstr,
    pwszIcon: Pcwstr,
}
#[repr(C)]
struct UserEntity {
    dwVersion: u32,
    cbId: u32,
    pbId: *const u8,
    pwszName: Pcwstr,
    pwszIcon: Pcwstr,
    pwszDisplayName: Pcwstr,
}
#[repr(C)]
struct ClientData {
    dwVersion: u32,
    cbClientDataJSON: u32,
    pbClientDataJSON: *const u8,
    pwszHashAlgId: Pcwstr,
}
#[repr(C)]
struct CoseParam {
    dwVersion: u32,
    pwszCredentialType: Pcwstr,
    lAlg: i32,
}
#[repr(C)]
struct CoseParams {
    cCredentialParameters: u32,
    pCredentialParameters: *const CoseParam,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Credential {
    dwVersion: u32,
    cbId: u32,
    pbId: *const u8,
    pwszCredentialType: Pcwstr,
}
#[repr(C)]
struct Credentials {
    cCredentials: u32,
    pCredentials: *const Credential,
}
#[repr(C)]
struct CredentialEx {
    dwVersion: u32,
    cbId: u32,
    pbId: *const u8,
    pwszCredentialType: Pcwstr,
    dwTransports: u32,
}
#[repr(C)]
struct CredentialList {
    cCredentials: u32,
    ppCredentials: *const *const CredentialEx,
}
#[repr(C)]
struct Extension {
    pwszExtensionIdentifier: Pcwstr,
    cbExtension: u32,
    pvExtension: *const c_void,
}
#[repr(C)]
struct Extensions {
    cExtensions: u32,
    pExtensions: *const Extension,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct HmacSalt {
    cbFirst: u32,
    pbFirst: *const u8,
    cbSecond: u32,
    pbSecond: *const u8,
}
#[repr(C)]
struct CredWithSalt {
    cbCredID: u32,
    pbCredID: *const u8,
    pHmacSecretSalt: *const HmacSalt,
}
#[repr(C)]
struct SaltValues {
    pGlobalHmacSalt: *const HmacSalt,
    cCredWithHmacSecretSaltList: u32,
    pCredWithHmacSecretSaltList: *const CredWithSalt,
}
#[repr(C)]
struct CredProtectIn {
    dwCredProtect: u32,
    bRequireCredProtect: Bool,
}
/// WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, all fields through
/// VERSION_9 (Windows reads it up to the `dwVersion` set).
#[repr(C)]
struct MakeCredOptions {
    dwVersion: u32,
    dwTimeoutMilliseconds: u32,
    CredentialList: Credentials,
    Extensions: Extensions,
    dwAuthenticatorAttachment: u32,
    bRequireResidentKey: Bool,
    dwUserVerificationRequirement: u32,
    dwAttestationConveyancePreference: u32,
    dwFlags: u32,
    // v2
    pCancellationId: *const Guid,
    // v3
    pExcludeCredentialList: *const CredentialList,
    // v4
    dwEnterpriseAttestation: u32,
    dwLargeBlobSupport: u32,
    bPreferResidentKey: Bool,
    // v5
    bBrowserInPrivateMode: Bool,
    // v6
    bEnablePrf: Bool,
    // v7
    pLinkedDevice: *const c_void,
    cbJsonExt: u32,
    pbJsonExt: *const u8,
    // v8
    pPRFGlobalEval: *const HmacSalt,
    cCredentialHints: u32,
    ppwszCredentialHints: *const Pcwstr,
    bThirdPartyPayment: Bool,
    // v9
    pwszRemoteWebOrigin: Pcwstr,
    cbPublicKeyCredentialCreationOptionsJSON: u32,
    pbPublicKeyCredentialCreationOptionsJSON: *const u8,
    cbAuthenticatorId: u32,
    pbAuthenticatorId: *const u8,
}
/// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS, all fields through
/// VERSION_9.
#[repr(C)]
struct GetAssertionOptions {
    dwVersion: u32,
    dwTimeoutMilliseconds: u32,
    CredentialList: Credentials,
    Extensions: Extensions,
    dwAuthenticatorAttachment: u32,
    dwUserVerificationRequirement: u32,
    dwFlags: u32,
    // v2
    pwszU2fAppId: Pcwstr,
    pbU2fAppId: *mut Bool,
    // v3
    pCancellationId: *const Guid,
    // v4
    pAllowCredentialList: *const CredentialList,
    // v5
    dwCredLargeBlobOperation: u32,
    cbCredLargeBlob: u32,
    pbCredLargeBlob: *const u8,
    // v6
    pHmacSecretSaltValues: *const SaltValues,
    bBrowserInPrivateMode: Bool,
    // v7
    pLinkedDevice: *const c_void,
    bAutoFill: Bool,
    cbJsonExt: u32,
    pbJsonExt: *const u8,
    // v8
    cCredentialHints: u32,
    ppwszCredentialHints: *const Pcwstr,
    // v9
    pwszRemoteWebOrigin: Pcwstr,
    cbPublicKeyCredentialRequestOptionsJSON: u32,
    pbPublicKeyCredentialRequestOptionsJSON: *const u8,
    cbAuthenticatorId: u32,
    pbAuthenticatorId: *const u8,
}
/// WEBAUTHN_CREDENTIAL_ATTESTATION through VERSION_8; read only up to its
/// own `dwVersion`.
#[repr(C)]
struct CredentialAttestation {
    dwVersion: u32,
    pwszFormatType: Pcwstr,
    cbAuthenticatorData: u32,
    pbAuthenticatorData: *mut u8,
    cbAttestation: u32,
    pbAttestation: *mut u8,
    dwAttestationDecodeType: u32,
    pvAttestationDecode: *mut c_void,
    cbAttestationObject: u32,
    pbAttestationObject: *mut u8,
    cbCredentialId: u32,
    pbCredentialId: *mut u8,
    // v2
    Extensions: Extensions,
    // v3
    dwUsedTransport: u32,
    // v4
    bEpAtt: Bool,
    bLargeBlobSupported: Bool,
    bResidentKey: Bool,
    // v5
    bPrfEnabled: Bool,
    // v6
    cbUnsignedExtensionOutputs: u32,
    pbUnsignedExtensionOutputs: *mut u8,
    // v7
    pHmacSecret: *mut HmacSalt,
    bThirdPartyPayment: Bool,
    // v8
    dwTransports: u32,
    cbClientDataJSON: u32,
    pbClientDataJSON: *mut u8,
    cbRegistrationResponseJSON: u32,
    pbRegistrationResponseJSON: *mut u8,
}
/// WEBAUTHN_ASSERTION through VERSION_6; read only up to its own
/// `dwVersion`.
#[repr(C)]
struct Assertion {
    dwVersion: u32,
    cbAuthenticatorData: u32,
    pbAuthenticatorData: *mut u8,
    cbSignature: u32,
    pbSignature: *mut u8,
    Credential: Credential,
    cbUserId: u32,
    pbUserId: *mut u8,
    // v2
    Extensions: Extensions,
    cbCredLargeBlob: u32,
    pbCredLargeBlob: *mut u8,
    dwCredLargeBlobStatus: u32,
    // v3
    pHmacSecret: *mut HmacSalt,
    // v4
    dwUsedTransport: u32,
    // v5
    cbUnsignedExtensionOutputs: u32,
    pbUnsignedExtensionOutputs: *mut u8,
    // v6
    cbClientDataJSON: u32,
    pbClientDataJSON: *mut u8,
    cbAuthenticationResponseJSON: u32,
    pbAuthenticationResponseJSON: *mut u8,
}

/// The 82 checks of spec Appendix A, each a `const` assertion; the tests
/// compare them with docs/webauthn-layout.txt.
macro_rules! layout {
    (
        $(size $name:literal $t:ty = $n:literal;)*
        $(off $oname:literal $ot:ident . $f:ident = $m:literal;)*
    ) => {
        $(const _: () = assert!(size_of::<$t>() == $n);)*
        $(const _: () = assert!(offset_of!($ot, $f) == $m);)*
        /// The checks as docs/webauthn-layout.txt lists them, measured on
        /// the definitions above.
        #[cfg(test)]
        fn layout_lines() -> Vec<String> {
            let mut lines = Vec::new();
            $(lines.push(format!("size {} {}", $name, size_of::<$t>()));)*
            $(lines.push(format!("off {}.{} {}", $oname, stringify!($f), offset_of!($ot, $f)));)*
            lines
        }
    };
}
layout! {
    size "WEBAUTHN_RP_ENTITY_INFORMATION" RpEntity = 32;
    size "WEBAUTHN_USER_ENTITY_INFORMATION" UserEntity = 40;
    size "WEBAUTHN_CLIENT_DATA" ClientData = 24;
    size "WEBAUTHN_COSE_CREDENTIAL_PARAMETER" CoseParam = 24;
    size "WEBAUTHN_COSE_CREDENTIAL_PARAMETERS" CoseParams = 16;
    size "WEBAUTHN_CREDENTIAL" Credential = 24;
    size "WEBAUTHN_CREDENTIALS" Credentials = 16;
    size "WEBAUTHN_CREDENTIAL_EX" CredentialEx = 32;
    size "WEBAUTHN_CREDENTIAL_LIST" CredentialList = 16;
    size "WEBAUTHN_EXTENSION" Extension = 24;
    size "WEBAUTHN_EXTENSIONS" Extensions = 16;
    size "WEBAUTHN_HMAC_SECRET_SALT" HmacSalt = 32;
    size "WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT" CredWithSalt = 24;
    size "WEBAUTHN_HMAC_SECRET_SALT_VALUES" SaltValues = 24;
    size "WEBAUTHN_CRED_PROTECT_EXTENSION_IN" CredProtectIn = 8;
    size "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions = 200;
    size "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions = 200;
    size "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation = 192;
    size "WEBAUTHN_ASSERTION" Assertion = 168;
    off "WEBAUTHN_USER_ENTITY_INFORMATION" UserEntity.pwszDisplayName = 32;
    off "WEBAUTHN_CLIENT_DATA" ClientData.pwszHashAlgId = 16;
    off "WEBAUTHN_COSE_CREDENTIAL_PARAMETER" CoseParam.lAlg = 16;
    off "WEBAUTHN_CREDENTIAL_EX" CredentialEx.dwTransports = 24;
    off "WEBAUTHN_EXTENSION" Extension.pvExtension = 16;
    off "WEBAUTHN_HMAC_SECRET_SALT" HmacSalt.pbSecond = 24;
    off "WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT" CredWithSalt.pHmacSecretSalt = 16;
    off "WEBAUTHN_HMAC_SECRET_SALT_VALUES" SaltValues.pCredWithHmacSecretSaltList = 16;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.CredentialList = 8;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.Extensions = 24;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.dwAuthenticatorAttachment = 40;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.dwFlags = 56;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.pCancellationId = 64;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.pExcludeCredentialList = 72;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.dwEnterpriseAttestation = 80;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.bPreferResidentKey = 88;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.bBrowserInPrivateMode = 92;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.bEnablePrf = 96;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.pLinkedDevice = 104;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.pbJsonExt = 120;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.pPRFGlobalEval = 128;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.ppwszCredentialHints = 144;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.bThirdPartyPayment = 152;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.pwszRemoteWebOrigin = 160;
    off "WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS" MakeCredOptions.pbAuthenticatorId = 192;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.dwFlags = 48;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pwszU2fAppId = 56;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pCancellationId = 72;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pAllowCredentialList = 80;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.dwCredLargeBlobOperation = 88;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pbCredLargeBlob = 96;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pHmacSecretSaltValues = 104;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.bBrowserInPrivateMode = 112;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pLinkedDevice = 120;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.bAutoFill = 128;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pbJsonExt = 136;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.ppwszCredentialHints = 152;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pwszRemoteWebOrigin = 160;
    off "WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS" GetAssertionOptions.pbAuthenticatorId = 192;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.pbAuthenticatorData = 24;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.pvAttestationDecode = 56;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.pbCredentialId = 88;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.Extensions = 96;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.dwUsedTransport = 112;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.bResidentKey = 124;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.bPrfEnabled = 128;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.pbUnsignedExtensionOutputs = 136;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.pHmacSecret = 144;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.bThirdPartyPayment = 152;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.dwTransports = 156;
    off "WEBAUTHN_CREDENTIAL_ATTESTATION" CredentialAttestation.pbRegistrationResponseJSON = 184;
    off "WEBAUTHN_ASSERTION" Assertion.pbAuthenticatorData = 8;
    off "WEBAUTHN_ASSERTION" Assertion.pbSignature = 24;
    off "WEBAUTHN_ASSERTION" Assertion.Credential = 32;
    off "WEBAUTHN_ASSERTION" Assertion.pbUserId = 64;
    off "WEBAUTHN_ASSERTION" Assertion.Extensions = 72;
    off "WEBAUTHN_ASSERTION" Assertion.pbCredLargeBlob = 96;
    off "WEBAUTHN_ASSERTION" Assertion.dwCredLargeBlobStatus = 104;
    off "WEBAUTHN_ASSERTION" Assertion.pHmacSecret = 112;
    off "WEBAUTHN_ASSERTION" Assertion.dwUsedTransport = 120;
    off "WEBAUTHN_ASSERTION" Assertion.pbUnsignedExtensionOutputs = 128;
    off "WEBAUTHN_ASSERTION" Assertion.pbClientDataJSON = 144;
    off "WEBAUTHN_ASSERTION" Assertion.pbAuthenticationResponseJSON = 160;
}

/// Cross-platform authenticators only: a security key, never Windows Hello.
const CROSS_PLATFORM: u32 = 2;
const ATTESTATION_NONE: u32 = 1;
const CRED_TYPE: &str = "public-key";
const HASH_ALG: &str = "SHA-256";
/// ES256 and EdDSA; the signature is never verified (spec §8.3).
const ALGORITHMS: [i32; 2] = [-7, -8];
const HINT: &str = "security-key";
const HMAC_SECRET: &str = "hmac-secret";
const CRED_PROTECT: &str = "credProtect";
/// The transports every allowed or excluded credential names.
const TRANSPORTS: u32 = fido::USB | fido::NFC;
/// No buffer of an answer is read beyond this many bytes.
const ANSWER_MAX: usize = 1 << 16;
/// An hmac-secret output is 32 bytes; a longer one is copied this far only
/// to be refused.
const OUTPUT_MAX: usize = 64;
const NTE_NOT_SUPPORTED: i32 = 0x8009_0029_u32 as i32;
const E_NOT_SUPPORTED: i32 = 0x8007_0032_u32 as i32;

/// The option struct versions an API version takes (spec §8.1): from API 9
/// on (9, 9), at 6 to 8 their own number, at 4 and 5 (5, 6).
pub fn versions(api: u32) -> (u32, u32) {
    match api {
        9.. => (9, 9),
        6..=8 => (api, api),
        _ => (5, 6),
    }
}

/// What the option structs point to, each buffer on the heap of its own,
/// so that every pointer stays valid wherever the owner moves.
#[derive(Default)]
struct Keep {
    text: Vec<Box<[u16]>>,
    bytes: Vec<Box<[u8]>>,
    credentials: Option<Box<[Credential]>>,
    ex: Option<Box<[CredentialEx]>>,
    ex_list: Option<Box<[*const CredentialEx]>>,
    list: Option<Box<CredentialList>>,
    cose: Option<Box<[CoseParam; 2]>>,
    extensions: Option<Box<[Extension; 2]>>,
    hmac_secret: Option<Box<Bool>>,
    cred_protect: Option<Box<CredProtectIn>>,
    salts: Option<Box<[HmacSalt]>>,
    with_salts: Option<Box<[CredWithSalt]>>,
    salt_values: Option<Box<SaltValues>>,
    cancel: Option<Box<Guid>>,
    hints: Option<Box<[Pcwstr; 1]>>,
}
impl Keep {
    fn wide(&mut self, s: &str) -> Pcwstr {
        let text: Box<[u16]> = s.encode_utf16().chain(Some(0)).collect();
        let p = text.as_ptr();
        self.text.push(text);
        p
    }
    fn bytes(&mut self, b: &[u8]) -> (u32, *const u8) {
        let b: Box<[u8]> = b.into();
        let out = (b.len() as u32, b.as_ptr());
        self.bytes.push(b);
        out
    }
    /// One credential list in both shapes: the legacy `CredentialList`
    /// and the `CredentialEx` list that later versions read instead, each
    /// entry with the transports USB and NFC. Null pointers when empty.
    fn credentials(&mut self, ids: &[(u32, *const u8)]) -> (Credentials, *const CredentialList) {
        let cred_type = self.wide(CRED_TYPE);
        let legacy: Box<[Credential]> = ids
            .iter()
            .map(|&(cb, pb)| Credential {
                dwVersion: 1,
                cbId: cb,
                pbId: pb,
                pwszCredentialType: cred_type,
            })
            .collect();
        let ex: Box<[CredentialEx]> = ids
            .iter()
            .map(|&(cb, pb)| CredentialEx {
                dwVersion: 1,
                cbId: cb,
                pbId: pb,
                pwszCredentialType: cred_type,
                dwTransports: TRANSPORTS,
            })
            .collect();
        let ex_list: Box<[*const CredentialEx]> =
            ex.iter().map(|c| c as *const CredentialEx).collect();
        let n = ids.len() as u32;
        let list = Box::new(CredentialList {
            cCredentials: n,
            ppCredentials: if n == 0 { null() } else { ex_list.as_ptr() },
        });
        let shapes = (
            Credentials {
                cCredentials: n,
                pCredentials: if n == 0 { null() } else { legacy.as_ptr() },
            },
            &*list as *const CredentialList,
        );
        self.credentials = Some(legacy);
        self.ex = Some(ex);
        self.ex_list = Some(ex_list);
        self.list = Some(list);
        shapes
    }
    fn cancel(&mut self, cancel: &Guid) -> *const Guid {
        &**self.cancel.insert(Box::new(*cancel))
    }
    /// The hints from version 8 on (spec §8.3): a security key.
    fn hints(&mut self, version: u32) -> (u32, *const Pcwstr) {
        if version < 8 {
            return (0, null());
        }
        let hint = self.wide(HINT);
        (1, self.hints.insert(Box::new([hint])).as_ptr())
    }
    fn client(&mut self, json: &[u8]) -> Box<ClientData> {
        let (cb, pb) = self.bytes(json);
        Box::new(ClientData {
            dwVersion: 1,
            cbClientDataJSON: cb,
            pbClientDataJSON: pb,
            pwszHashAlgId: self.wide(HASH_ALG),
        })
    }
}

/// Everything a MakeCredential call reads, owned (spec §8.3): the structs
/// Windows gets and every array, string and extension they point to.
pub struct MakeOptions {
    pub owner: Hwnd,
    rp: Box<RpEntity>,
    user: Box<UserEntity>,
    params: Box<CoseParams>,
    client: Box<ClientData>,
    options: Box<MakeCredOptions>,
    /// Only held: it owns what the structs point to.
    #[cfg_attr(not(test), allow(dead_code))]
    keep: Keep,
}
/// Everything a GetAssertion call reads, owned.
pub struct AssertOptions {
    pub owner: Hwnd,
    rp_id: Box<[u16]>,
    client: Box<ClientData>,
    options: Box<GetAssertionOptions>,
    #[cfg_attr(not(test), allow(dead_code))]
    keep: Keep,
}

/// MakeCredential's arguments for `r` at API `api` (spec §8.3), with no
/// Windows call: the options version of `versions`, a resident credential
/// of a cross-platform key, hmac-secret on, credProtect 3 required in PIN
/// mode and 2 otherwise, the UV of the request, no attestation, the
/// exclude list, the cancel GUID, the hints from version 8, the timeout.
pub fn build_make_options(r: &MakeRequest, api: u32, cancel: &Guid) -> MakeOptions {
    let version = versions(api).0;
    let mut keep = Keep::default();
    let rp = Box::new(RpEntity {
        dwVersion: 1,
        pwszId: keep.wide(fido::RP_ID),
        pwszName: keep.wide(fido::RP_NAME),
        pwszIcon: null(),
    });
    let (cb_id, pb_id) = keep.bytes(&r.user_id);
    let user = Box::new(UserEntity {
        dwVersion: 1,
        cbId: cb_id,
        pbId: pb_id,
        pwszName: keep.wide(&r.name),
        pwszIcon: null(),
        pwszDisplayName: keep.wide(&r.display_name),
    });
    let cred_type = keep.wide(CRED_TYPE);
    let cose = keep.cose.insert(Box::new(ALGORITHMS.map(|alg| CoseParam {
        dwVersion: 1,
        pwszCredentialType: cred_type,
        lAlg: alg,
    })));
    let params = Box::new(CoseParams {
        cCredentialParameters: 2,
        pCredentialParameters: cose.as_ptr(),
    });
    let client = keep.client(&r.client_data);
    let hmac_secret: *const Bool = &**keep.hmac_secret.insert(Box::new(1));
    let (level, required) = r.cred_protect;
    let cred_protect: *const CredProtectIn = &**keep.cred_protect.insert(Box::new(CredProtectIn {
        dwCredProtect: level,
        bRequireCredProtect: Bool::from(required),
    }));
    let extensions = [
        Extension {
            pwszExtensionIdentifier: keep.wide(HMAC_SECRET),
            cbExtension: size_of::<Bool>() as u32,
            pvExtension: hmac_secret.cast(),
        },
        Extension {
            pwszExtensionIdentifier: keep.wide(CRED_PROTECT),
            cbExtension: size_of::<CredProtectIn>() as u32,
            pvExtension: cred_protect.cast(),
        },
    ];
    let extensions = keep.extensions.insert(Box::new(extensions)).as_ptr();
    let ids: Vec<(u32, *const u8)> = r.exclude.iter().map(|id| keep.bytes(id)).collect();
    let (legacy, exclude) = keep.credentials(&ids);
    let cancel = keep.cancel(cancel);
    let (hints, hint_list) = keep.hints(version);
    let options = Box::new(MakeCredOptions {
        dwVersion: version,
        dwTimeoutMilliseconds: fido::TIMEOUT_MS,
        CredentialList: legacy,
        Extensions: Extensions {
            cExtensions: 2,
            pExtensions: extensions,
        },
        dwAuthenticatorAttachment: CROSS_PLATFORM,
        bRequireResidentKey: 1,
        dwUserVerificationRequirement: r.uv as u32,
        dwAttestationConveyancePreference: ATTESTATION_NONE,
        dwFlags: 0,
        pCancellationId: cancel,
        pExcludeCredentialList: exclude,
        dwEnterpriseAttestation: 0,
        dwLargeBlobSupport: 0,
        bPreferResidentKey: 0,
        bBrowserInPrivateMode: 0,
        bEnablePrf: 0,
        pLinkedDevice: null(),
        cbJsonExt: 0,
        pbJsonExt: null(),
        pPRFGlobalEval: null(),
        cCredentialHints: hints,
        ppwszCredentialHints: hint_list,
        bThirdPartyPayment: 0,
        pwszRemoteWebOrigin: null(),
        cbPublicKeyCredentialCreationOptionsJSON: 0,
        pbPublicKeyCredentialCreationOptionsJSON: null(),
        cbAuthenticatorId: 0,
        pbAuthenticatorId: null(),
    });
    MakeOptions {
        owner: r.owner,
        rp,
        user,
        params,
        client,
        options,
        keep,
    }
}

/// GetAssertion's arguments for `r` at API `api` (spec §8.3), with no
/// Windows call: the options version of `versions`; the allow list in
/// `pAllowCredentialList` and the legacy list; one `CredWithSalt` per
/// allowed credential with its 32-byte salt and its second salt or none,
/// no global salt, and the flag that passes them to the key as they are;
/// the UV of the request; the cancel GUID; the hints from version 8; the
/// timeout.
pub fn build_assert_options(r: &AssertRequest, api: u32, cancel: &Guid) -> AssertOptions {
    let version = versions(api).1;
    let mut keep = Keep::default();
    let ids: Vec<(u32, *const u8)> = r.allow.iter().map(|(id, ..)| keep.bytes(id)).collect();
    let (legacy, allow) = keep.credentials(&ids);
    let salts: Box<[HmacSalt]> = r
        .allow
        .iter()
        .map(|(_, first, second)| {
            let (cb_first, pb_first) = keep.bytes(first);
            let (cb_second, pb_second) = match second {
                Some(second) => keep.bytes(second),
                None => (0, null()),
            };
            HmacSalt {
                cbFirst: cb_first,
                pbFirst: pb_first,
                cbSecond: cb_second,
                pbSecond: pb_second,
            }
        })
        .collect();
    let salts = keep.salts.insert(salts);
    let with_salts: Box<[CredWithSalt]> = ids
        .iter()
        .zip(salts.iter())
        .map(|(&(cb, pb), salt)| CredWithSalt {
            cbCredID: cb,
            pbCredID: pb,
            pHmacSecretSalt: salt,
        })
        .collect();
    let with_salts = keep.with_salts.insert(with_salts);
    let n = with_salts.len() as u32;
    let list = if n == 0 { null() } else { with_salts.as_ptr() };
    let salt_values: *const SaltValues = &**keep.salt_values.insert(Box::new(SaltValues {
        pGlobalHmacSalt: null(),
        cCredWithHmacSecretSaltList: n,
        pCredWithHmacSecretSaltList: list,
    }));
    let client = keep.client(&r.client_data);
    let cancel = keep.cancel(cancel);
    let (hints, hint_list) = keep.hints(version);
    let options = Box::new(GetAssertionOptions {
        dwVersion: version,
        dwTimeoutMilliseconds: fido::TIMEOUT_MS,
        CredentialList: legacy,
        Extensions: Extensions {
            cExtensions: 0,
            pExtensions: null(),
        },
        dwAuthenticatorAttachment: CROSS_PLATFORM,
        dwUserVerificationRequirement: r.uv as u32,
        dwFlags: fido::HMAC_SECRET_VALUES_FLAG,
        pwszU2fAppId: null(),
        pbU2fAppId: null_mut(),
        pCancellationId: cancel,
        pAllowCredentialList: allow,
        dwCredLargeBlobOperation: 0,
        cbCredLargeBlob: 0,
        pbCredLargeBlob: null(),
        pHmacSecretSaltValues: salt_values,
        bBrowserInPrivateMode: 0,
        pLinkedDevice: null(),
        bAutoFill: 0,
        cbJsonExt: 0,
        pbJsonExt: null(),
        cCredentialHints: hints,
        ppwszCredentialHints: hint_list,
        pwszRemoteWebOrigin: null(),
        cbPublicKeyCredentialRequestOptionsJSON: 0,
        pbPublicKeyCredentialRequestOptionsJSON: null(),
        cbAuthenticatorId: 0,
        pbAuthenticatorId: null(),
    });
    AssertOptions {
        owner: r.owner,
        rp_id: fido::RP_ID.encode_utf16().chain(Some(0)).collect(),
        client,
        options,
        keep,
    }
}

/// A copy of `cb` bytes at `pb`; none from a null pointer, and none from a
/// length no answer has.
///
/// # Safety
/// `pb` is null or points to `cb` readable bytes.
unsafe fn copy(cb: u32, pb: *const u8) -> Vec<u8> {
    let cb = cb as usize;
    if pb.is_null() || cb > ANSWER_MAX {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(pb, cb) }.to_vec()
}
/// An hmac-secret output: none from a null pointer or a zero length; at
/// most OUTPUT_MAX bytes, so that a wrong length is still refused.
///
/// # Safety
/// `pb` is null or points to `cb` readable bytes.
unsafe fn output(cb: u32, pb: *const u8) -> Option<Zeroizing<Vec<u8>>> {
    if pb.is_null() || cb == 0 {
        return None;
    }
    let n = (cb as usize).min(OUTPUT_MAX);
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    out.extend_from_slice(unsafe { std::slice::from_raw_parts(pb, n) });
    Some(out)
}
/// Zeroes `cb` bytes at `p` in a way the compiler keeps.
///
/// # Safety
/// `p` is null or points to `cb` writable bytes.
unsafe fn wipe(p: *const u8, cb: u32) {
    if p.is_null() {
        return;
    }
    let p = p.cast_mut();
    for i in 0..cb as usize {
        unsafe { std::ptr::write_volatile(p.add(i), 0) };
    }
}

/// What the app needs of Windows' attestation, read only up to its own
/// `dwVersion` (spec §8.1, §8.4), then every buffer of it that may hold
/// the key's answer wiped: the unsigned extension outputs (v6), the
/// hmac-secret outputs (v7) and the JSON (v8). `free` then gets it.
///
/// # Safety
/// `p` points to an attestation as large as its `dwVersion` says, with
/// valid buffers.
unsafe fn take_attestation(
    p: *mut CredentialAttestation,
    free: impl FnOnce(*mut CredentialAttestation),
) -> RawCredential {
    let raw = unsafe {
        let version = addr_of!((*p).dwVersion).read();
        RawCredential {
            version,
            cred_id: copy(
                addr_of!((*p).cbCredentialId).read(),
                addr_of!((*p).pbCredentialId).read(),
            ),
            auth_data: copy(
                addr_of!((*p).cbAuthenticatorData).read(),
                addr_of!((*p).pbAuthenticatorData).read(),
            ),
            transport: (version >= 3).then(|| addr_of!((*p).dwUsedTransport).read()),
        }
    };
    unsafe {
        let version = raw.version;
        if version >= 6 {
            wipe(
                addr_of!((*p).pbUnsignedExtensionOutputs).read(),
                addr_of!((*p).cbUnsignedExtensionOutputs).read(),
            );
        }
        if version >= 7 {
            let salt = addr_of!((*p).pHmacSecret).read();
            if !salt.is_null() {
                let s = salt.read();
                wipe(s.pbFirst, s.cbFirst);
                wipe(s.pbSecond, s.cbSecond);
            }
        }
        if version >= 8 {
            wipe(
                addr_of!((*p).pbClientDataJSON).read(),
                addr_of!((*p).cbClientDataJSON).read(),
            );
            wipe(
                addr_of!((*p).pbRegistrationResponseJSON).read(),
                addr_of!((*p).cbRegistrationResponseJSON).read(),
            );
        }
    }
    free(p);
    raw
}
/// What the app needs of Windows' assertion, read only up to its own
/// `dwVersion` (spec §8.1, §8.4: a version-3 assertion has no transport,
/// and nothing past its version-3 fields is read), then every buffer of it
/// that may hold the key's answer wiped: the hmac-secret outputs (v3), the
/// unsigned extension outputs (v5) and the JSON (v6). `free` then gets it.
///
/// # Safety
/// `p` points to an assertion as large as its `dwVersion` says, with valid
/// buffers.
unsafe fn take_assertion(p: *mut Assertion, free: impl FnOnce(*mut Assertion)) -> RawAssertion {
    let raw = unsafe {
        let version = addr_of!((*p).dwVersion).read();
        let credential = addr_of!((*p).Credential).read();
        let salt = if version >= 3 {
            addr_of!((*p).pHmacSecret).read()
        } else {
            null_mut()
        };
        let (first, second) = if salt.is_null() {
            (None, None)
        } else {
            let s = salt.read();
            (output(s.cbFirst, s.pbFirst), output(s.cbSecond, s.pbSecond))
        };
        RawAssertion {
            version,
            auth_data: copy(
                addr_of!((*p).cbAuthenticatorData).read(),
                addr_of!((*p).pbAuthenticatorData).read(),
            ),
            cred_id: copy(credential.cbId, credential.pbId),
            first,
            second,
            transport: (version >= 4).then(|| addr_of!((*p).dwUsedTransport).read()),
        }
    };
    unsafe {
        let version = raw.version;
        if version >= 3 {
            let salt = addr_of!((*p).pHmacSecret).read();
            if !salt.is_null() {
                let s = salt.read();
                wipe(s.pbFirst, s.cbFirst);
                wipe(s.pbSecond, s.cbSecond);
            }
        }
        if version >= 5 {
            wipe(
                addr_of!((*p).pbUnsignedExtensionOutputs).read(),
                addr_of!((*p).cbUnsignedExtensionOutputs).read(),
            );
        }
        if version >= 6 {
            wipe(
                addr_of!((*p).pbClientDataJSON).read(),
                addr_of!((*p).cbClientDataJSON).read(),
            );
            wipe(
                addr_of!((*p).pbAuthenticationResponseJSON).read(),
                addr_of!((*p).cbAuthenticationResponseJSON).read(),
            );
        }
    }
    free(p);
    raw
}

/// The error a failed call stands for (spec §8.7), from its HRESULT and
/// from the W3C DOM error Windows maps it to; Windows' own name and text
/// for it are never shown. A code it does not know is shown as a number.
/// `make`: a MakeCredential, and whether it required credProtect. The
/// HRESULT's own meaning comes first: NTE_INVALID_PARAMETER is a request
/// Windows refused, whatever DOM error it maps to.
fn error_of(hr: Hresult, dom: Hresult, make: Option<bool>) -> FidoError {
    match FidoError::from_hresult(hr) {
        FidoError::Other(_) => {}
        known => return known,
    }
    let is = |code: Hresult| hr == code || dom == code;
    match make {
        // InvalidStateError: the key holds an excluded credential.
        Some(_) if is(fido::NTE_EXISTS) => FidoError::Exists,
        // NotSupported at a registration: in PIN mode the required
        // credProtect, else hmac-secret.
        Some(required) if is(NTE_NOT_SUPPORTED) || is(E_NOT_SUPPORTED) => {
            if required {
                FidoError::NoCredProtect
            } else {
                FidoError::NoHmacSecret
            }
        }
        _ if is(fido::E_CANCELLED) => FidoError::Cancelled,
        _ => FidoError::Other(hr),
    }
}

/// Windows' dialogs belong to the app's top-level window. With none (hWnd
/// 0) Windows fails at once with NTE_INVALID_PARAMETER (a real YubiKey,
/// spec §2.28), so no such call is made.
fn owner_set(owner: Hwnd) -> Result<(), FidoError> {
    if owner == 0 {
        return Err(FidoError::Rejected);
    }
    Ok(())
}

type FnVersion = unsafe extern "system" fn() -> u32;
type FnMake = unsafe extern "system" fn(
    Hwnd,
    *const RpEntity,
    *const UserEntity,
    *const CoseParams,
    *const ClientData,
    *const MakeCredOptions,
    *mut *mut CredentialAttestation,
) -> Hresult;
type FnGet = unsafe extern "system" fn(
    Hwnd,
    Pcwstr,
    *const ClientData,
    *const GetAssertionOptions,
    *mut *mut Assertion,
) -> Hresult;
type FnFreeAttestation = unsafe extern "system" fn(*mut CredentialAttestation);
type FnFreeAssertion = unsafe extern "system" fn(*mut Assertion);
type FnCancelId = unsafe extern "system" fn(*mut Guid) -> Hresult;
type FnCancel = unsafe extern "system" fn(*const Guid) -> Hresult;
type FnErrorName = unsafe extern "system" fn(Hresult) -> Pcwstr;
type FnDomError = unsafe extern "system" fn(Hresult) -> Hresult;
/// The nine exports (spec §8.1).
struct Api {
    version: FnVersion,
    make: FnMake,
    get: FnGet,
    free_attestation: FnFreeAttestation,
    free_assertion: FnFreeAssertion,
    cancel_id: FnCancelId,
    cancel: FnCancel,
    /// Resolved with the others, so that a DLL without it is not used;
    /// never called: Windows' text for an error is never shown.
    #[allow(dead_code)]
    error_name: FnErrorName,
    dom_error: FnDomError,
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: isize, flags: u32) -> isize;
    fn GetProcAddress(module: isize, name: *const u8) -> *const c_void;
}
/// webauthn.dll from System32 with its nine exports, loaded once and never
/// freed, like wtsapi32 (spec §8.1); None when it is missing or lacks one.
fn library() -> Option<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(|| {
        let name: Vec<u16> = "webauthn.dll".encode_utf16().chain(Some(0)).collect();
        // LOAD_LIBRARY_SEARCH_SYSTEM32, which also applies to the DLL's
        // own dependencies.
        let module = unsafe { LoadLibraryExW(name.as_ptr(), 0, 0x800) };
        if module == 0 {
            return None;
        }
        let export = |name: &CStr| {
            let p = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
            (!p.is_null()).then_some(p)
        };
        use std::mem::transmute as fun;
        unsafe {
            Some(Api {
                version: fun::<*const c_void, FnVersion>(export(c"WebAuthNGetApiVersionNumber")?),
                make: fun::<*const c_void, FnMake>(export(c"WebAuthNAuthenticatorMakeCredential")?),
                get: fun::<*const c_void, FnGet>(export(c"WebAuthNAuthenticatorGetAssertion")?),
                free_attestation: fun::<*const c_void, FnFreeAttestation>(export(
                    c"WebAuthNFreeCredentialAttestation",
                )?),
                free_assertion: fun::<*const c_void, FnFreeAssertion>(export(
                    c"WebAuthNFreeAssertion",
                )?),
                cancel_id: fun::<*const c_void, FnCancelId>(export(c"WebAuthNGetCancellationId")?),
                cancel: fun::<*const c_void, FnCancel>(export(c"WebAuthNCancelCurrentOperation")?),
                error_name: fun::<*const c_void, FnErrorName>(export(c"WebAuthNGetErrorName")?),
                dom_error: fun::<*const c_void, FnDomError>(export(
                    c"WebAuthNGetW3CExceptionDOMError",
                )?),
            })
        }
    })
    .as_ref()
}
/// The API version of webauthn.dll when it loads with every export, for
/// the self-check's informational line (spec §8.8); no ceremony.
pub fn api_version() -> Option<u32> {
    library().map(|api| unsafe { (api.version)() })
}

/// Windows' WebAuthn API behind the app's `Authenticator` (spec §8.5).
/// Each call builds its options on the worker thread that makes it, which
/// owns them until the call returns.
pub struct WebAuthn {
    api: &'static Api,
    version: u32,
}
impl WebAuthn {
    /// webauthn.dll with API 4 or later (spec §8.1); S-NOAPI otherwise.
    pub fn load() -> Result<Arc<dyn Authenticator>, FidoError> {
        let api = library().ok_or(FidoError::NoApi)?;
        let version = unsafe { (api.version)() };
        if version < 4 {
            return Err(FidoError::NoApi);
        }
        Ok(Arc::new(Self { api, version }))
    }
    fn error(&self, hr: Hresult, make: Option<bool>) -> FidoError {
        error_of(hr, unsafe { (self.api.dom_error)(hr) }, make)
    }
}
impl Authenticator for WebAuthn {
    fn api_version(&self) -> u32 {
        self.version
    }
    fn new_cancel(&self) -> Result<CancelToken, FidoError> {
        let mut guid = Guid::default();
        let hr = unsafe { (self.api.cancel_id)(&mut guid) };
        if hr < 0 {
            return Err(FidoError::Other(hr));
        }
        Ok(CancelToken::new(guid.bytes()))
    }
    fn make_credential(
        &self,
        r: &MakeRequest,
        c: &CancelToken,
    ) -> Result<RawCredential, FidoError> {
        let o = build_make_options(r, self.version, &Guid::of(&c.id));
        owner_set(o.owner)?;
        // A cancel that came before the call: no Windows dialog opens
        // (spec §8.5), since Windows forgets a cancel with nothing running.
        c.check()?;
        let mut out = null_mut();
        let hr = unsafe {
            (self.api.make)(
                o.owner,
                &*o.rp,
                &*o.user,
                &*o.params,
                &*o.client,
                &*o.options,
                &mut out,
            )
        };
        let free = self.api.free_attestation;
        let raw = (!out.is_null()).then(|| unsafe { take_attestation(out, |p| free(p)) });
        if hr < 0 {
            return Err(self.error(hr, Some(r.cred_protect.1)));
        }
        raw.ok_or(FidoError::Unverifiable)
    }
    fn get_assertion(&self, r: &AssertRequest, c: &CancelToken) -> Result<RawAssertion, FidoError> {
        let o = build_assert_options(r, self.version, &Guid::of(&c.id));
        owner_set(o.owner)?;
        c.check()?;
        let mut out = null_mut();
        let hr =
            unsafe { (self.api.get)(o.owner, o.rp_id.as_ptr(), &*o.client, &*o.options, &mut out) };
        let free = self.api.free_assertion;
        let raw = (!out.is_null()).then(|| unsafe { take_assertion(out, |p| free(p)) });
        if hr < 0 {
            return Err(self.error(hr, None));
        }
        raw.ok_or(FidoError::Unverifiable)
    }
    fn cancel(&self, c: &CancelToken) {
        let guid = Guid::of(&c.id);
        unsafe {
            (self.api.cancel)(&guid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use goyo_vault::fido::{Uv, check_assertion};

    /// The layout of every struct, as `const` assertions hold it, is the
    /// table docs/webauthn-layout.txt records (spec §14.8-13).
    #[test]
    fn the_layout_is_the_recorded_table() {
        let recorded = include_str!("../docs/webauthn-layout.txt");
        let recorded: Vec<&str> = recorded
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        assert_eq!(recorded.len(), 82);
        assert_eq!(layout_lines(), recorded);
        for (api, expected) in [
            (4, (5, 6)),
            (5, (5, 6)),
            (6, (6, 6)),
            (7, (7, 7)),
            (8, (8, 8)),
            (9, (9, 9)),
            (12, (9, 9)),
        ] {
            assert_eq!(versions(api), expected, "API {api}");
        }
        let id: [u8; 16] = std::array::from_fn(|i| i as u8 * 17);
        assert_eq!(Guid::of(&id).bytes(), id);
    }

    /// The text a wide string pointer names.
    fn text(p: Pcwstr) -> String {
        assert!(!p.is_null());
        let mut n = 0;
        while unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(p, n) }).unwrap()
    }
    fn bytes(cb: u32, pb: *const u8) -> Vec<u8> {
        assert!(!pb.is_null());
        unsafe { std::slice::from_raw_parts(pb, cb as usize) }.to_vec()
    }
    /// Every heap block the options own, as address ranges.
    fn owned(keep: &Keep, structs: &[(usize, usize)]) -> Vec<(usize, usize)> {
        fn range<T: ?Sized>(b: &T) -> (usize, usize) {
            let start = b as *const T as *const u8 as usize;
            (start, start + size_of_val(b))
        }
        let mut out = structs.to_vec();
        out.extend(keep.text.iter().map(|b| range(&**b)));
        out.extend(keep.bytes.iter().map(|b| range(&**b)));
        out.extend(keep.credentials.iter().map(|b| range(&**b)));
        out.extend(keep.ex.iter().map(|b| range(&**b)));
        out.extend(keep.ex_list.iter().map(|b| range(&**b)));
        out.extend(keep.list.iter().map(|b| range(&**b)));
        out.extend(keep.cose.iter().map(|b| range(&**b)));
        out.extend(keep.extensions.iter().map(|b| range(&**b)));
        out.extend(keep.hmac_secret.iter().map(|b| range(&**b)));
        out.extend(keep.cred_protect.iter().map(|b| range(&**b)));
        out.extend(keep.salts.iter().map(|b| range(&**b)));
        out.extend(keep.with_salts.iter().map(|b| range(&**b)));
        out.extend(keep.salt_values.iter().map(|b| range(&**b)));
        out.extend(keep.cancel.iter().map(|b| range(&**b)));
        out.extend(keep.hints.iter().map(|b| range(&**b)));
        out
    }
    /// A pointer into one of the blocks the options own.
    fn inside<T>(p: *const T, owned: &[(usize, usize)]) -> bool {
        let p = p as usize;
        owned.iter().any(|(start, end)| (*start..*end).contains(&p))
    }
    fn of<T>(b: &T) -> (usize, usize) {
        let start = b as *const T as usize;
        (start, start + size_of::<T>())
    }
    /// The credential lists in both shapes hold `ids`, each with USB and
    /// NFC, and every pointer stays in the options.
    fn check_lists(
        legacy: &Credentials,
        ex: *const CredentialList,
        ids: &[Vec<u8>],
        owned: &[(usize, usize)],
    ) {
        assert!(inside(ex, owned));
        let ex = unsafe { &*ex };
        assert_eq!(legacy.cCredentials as usize, ids.len());
        assert_eq!(ex.cCredentials as usize, ids.len());
        if ids.is_empty() {
            assert!(legacy.pCredentials.is_null() && ex.ppCredentials.is_null());
            return;
        }
        assert!(inside(legacy.pCredentials, owned) && inside(ex.ppCredentials, owned));
        for (i, id) in ids.iter().enumerate() {
            let c = unsafe { &*legacy.pCredentials.add(i) };
            assert_eq!(c.dwVersion, 1);
            assert!(inside(c.pbId, owned));
            assert_eq!(&bytes(c.cbId, c.pbId), id);
            assert_eq!(text(c.pwszCredentialType), "public-key");
            let p = unsafe { *ex.ppCredentials.add(i) };
            assert!(inside(p, owned));
            let c = unsafe { &*p };
            assert_eq!(c.dwVersion, 1);
            assert!(inside(c.pbId, owned));
            assert_eq!(&bytes(c.cbId, c.pbId), id);
            assert_eq!(text(c.pwszCredentialType), "public-key");
            assert_eq!(c.dwTransports, fido::USB | fido::NFC);
        }
    }

    /// MakeCredential's options, field by field, at API 4 to 9 (spec
    /// §14.8-2): pure, every pointer into the value itself, which still
    /// holds after the value moved.
    #[test]
    fn make_options_are_built_field_by_field() {
        let cancel = Guid::of(&[0x5c; 16]);
        for pin in [false, true] {
            for api in 4..=9 {
                let exclude = vec![vec![1; 16], vec![2; 1023], vec![3; 64]];
                let request = MakeRequest {
                    owner: 0x1234,
                    user_id: [0x75; 32],
                    name: "goyo-ABABABAB-3-20260101-000001".into(),
                    display_name: "Goyo Vault ABABABAB key 3 20260101-000001".into(),
                    client_data: b"{\"type\":\"webauthn.create\"}".to_vec(),
                    uv: Uv::of(pin),
                    cred_protect: if pin { (3, true) } else { (2, false) },
                    exclude: exclude.clone(),
                };
                let built = build_make_options(&request, api, &cancel);
                // Moved: the boxes keep every address.
                let moved = [built];
                let m = &moved[0];
                let o = &*m.options;
                let owned = owned(
                    &m.keep,
                    &[
                        of(&*m.rp),
                        of(&*m.user),
                        of(&*m.params),
                        of(&*m.client),
                        of(o),
                    ],
                );
                assert_eq!(m.owner, 0x1234);
                assert_eq!(o.dwVersion, versions(api).0, "API {api}");
                assert_eq!(o.dwTimeoutMilliseconds, 120_000);
                assert_eq!(o.dwAuthenticatorAttachment, 2);
                assert_eq!(o.bRequireResidentKey, 1);
                assert_eq!(o.bPreferResidentKey, 0);
                assert_eq!(o.dwUserVerificationRequirement, if pin { 1 } else { 3 });
                assert_eq!(o.dwAttestationConveyancePreference, 1);
                assert_eq!(o.dwFlags, 0);
                assert!(inside(o.pCancellationId, &owned));
                assert_eq!(unsafe { *o.pCancellationId }, cancel);
                check_lists(
                    &o.CredentialList,
                    o.pExcludeCredentialList,
                    &exclude,
                    &owned,
                );
                // hmac-secret as a BOOL, credProtect {3, TRUE} or {2, FALSE}.
                assert_eq!(o.Extensions.cExtensions, 2);
                assert!(inside(o.Extensions.pExtensions, &owned));
                let ext = unsafe { std::slice::from_raw_parts(o.Extensions.pExtensions, 2) };
                assert_eq!(text(ext[0].pwszExtensionIdentifier), "hmac-secret");
                assert_eq!(ext[0].cbExtension, 4);
                assert!(inside(ext[0].pvExtension, &owned));
                assert_eq!(unsafe { *ext[0].pvExtension.cast::<Bool>() }, 1);
                assert_eq!(text(ext[1].pwszExtensionIdentifier), "credProtect");
                assert_eq!(ext[1].cbExtension, 8);
                assert!(inside(ext[1].pvExtension, &owned));
                let protect = unsafe { &*ext[1].pvExtension.cast::<CredProtectIn>() };
                assert_eq!(
                    (protect.dwCredProtect, protect.bRequireCredProtect),
                    if pin { (3, 1) } else { (2, 0) }
                );
                // Hints from version 8 only; nothing of a later version.
                if o.dwVersion >= 8 {
                    assert_eq!(o.cCredentialHints, 1);
                    assert!(inside(o.ppwszCredentialHints, &owned));
                    let hint = unsafe { *o.ppwszCredentialHints };
                    assert!(inside(hint, &owned));
                    assert_eq!(text(hint), "security-key");
                } else {
                    assert_eq!(o.cCredentialHints, 0);
                    assert!(o.ppwszCredentialHints.is_null());
                }
                assert_eq!(
                    (
                        o.dwEnterpriseAttestation,
                        o.dwLargeBlobSupport,
                        o.bEnablePrf
                    ),
                    (0, 0, 0)
                );
                assert!(o.pLinkedDevice.is_null() && o.pPRFGlobalEval.is_null());
                assert!(o.pbJsonExt.is_null() && o.pwszRemoteWebOrigin.is_null());
                assert!(o.pbAuthenticatorId.is_null());
                assert!(o.pbPublicKeyCredentialCreationOptionsJSON.is_null());
                // The RP, the user, the algorithms and the client data.
                assert_eq!(m.rp.dwVersion, 1);
                assert_eq!(text(m.rp.pwszId), "goyo-vault.invalid");
                assert_eq!(text(m.rp.pwszName), "Goyo Vault");
                assert!(m.rp.pwszIcon.is_null());
                assert!(inside(m.rp.pwszId, &owned) && inside(m.rp.pwszName, &owned));
                assert_eq!(m.user.dwVersion, 1);
                assert!(inside(m.user.pbId, &owned));
                assert_eq!(bytes(m.user.cbId, m.user.pbId), [0x75; 32]);
                assert_eq!(text(m.user.pwszName), request.name);
                assert_eq!(text(m.user.pwszDisplayName), request.display_name);
                assert_eq!(m.params.cCredentialParameters, 2);
                assert!(inside(m.params.pCredentialParameters, &owned));
                let cose = unsafe { std::slice::from_raw_parts(m.params.pCredentialParameters, 2) };
                for (c, alg) in cose.iter().zip([-7, -8]) {
                    assert_eq!((c.dwVersion, c.lAlg), (1, alg));
                    assert_eq!(text(c.pwszCredentialType), "public-key");
                }
                assert_eq!(m.client.dwVersion, 1);
                assert!(inside(m.client.pbClientDataJSON, &owned));
                assert_eq!(
                    bytes(m.client.cbClientDataJSON, m.client.pbClientDataJSON),
                    request.client_data
                );
                assert_eq!(text(m.client.pwszHashAlgId), "SHA-256");
            }
        }
    }

    /// GetAssertion's options, field by field, at API 4 to 9 (spec
    /// §14.8-2): the version, the flag on every assertion, one salt entry
    /// per allowed credential with 32/32 or 32/0 (a null second) and no
    /// global salt, the allow list in both shapes, UV, attachment, cancel,
    /// timeout, hints from version 8 only, every pointer inside.
    #[test]
    fn assert_options_are_built_field_by_field() {
        let cancel = Guid::of(&[0xc5; 16]);
        for pin in [false, true] {
            for n in [1, 3, 8] {
                for api in 4..=9 {
                    let allow: Vec<fido::Allowed> = (0..n)
                        .map(|i| {
                            let second = (i % 2 == 1).then_some([0xb0 + i as u8; 32]);
                            (vec![i as u8; 16 + 100 * i], [0xa0 + i as u8; 32], second)
                        })
                        .collect();
                    let request = AssertRequest::new(0x4321, allow.clone(), pin).unwrap();
                    let built = [build_assert_options(&request, api, &cancel)];
                    let a = &built[0];
                    let o = &*a.options;
                    let owned = owned(&a.keep, &[of(&*a.client), of(o)]);
                    assert_eq!(a.owner, 0x4321);
                    assert_eq!(o.dwVersion, versions(api).1, "API {api}");
                    assert!(o.dwVersion >= 6);
                    assert_eq!(o.dwTimeoutMilliseconds, 120_000);
                    assert_eq!(o.dwAuthenticatorAttachment, 2);
                    assert_eq!(o.dwUserVerificationRequirement, if pin { 1 } else { 3 });
                    assert_eq!(o.dwFlags, 0x0010_0000);
                    assert_eq!(o.Extensions.cExtensions, 0);
                    assert!(o.pwszU2fAppId.is_null() && o.pbU2fAppId.is_null());
                    assert!(inside(o.pCancellationId, &owned));
                    assert_eq!(unsafe { *o.pCancellationId }, cancel);
                    let ids: Vec<Vec<u8>> = allow.iter().map(|(id, ..)| id.clone()).collect();
                    check_lists(&o.CredentialList, o.pAllowCredentialList, &ids, &owned);
                    assert!(inside(o.pHmacSecretSaltValues, &owned));
                    let values = unsafe { &*o.pHmacSecretSaltValues };
                    assert!(values.pGlobalHmacSalt.is_null());
                    assert_eq!(values.cCredWithHmacSecretSaltList as usize, n);
                    assert!(inside(values.pCredWithHmacSecretSaltList, &owned));
                    for (i, (id, first, second)) in allow.iter().enumerate() {
                        let entry = unsafe { &*values.pCredWithHmacSecretSaltList.add(i) };
                        assert!(inside(entry.pbCredID, &owned));
                        assert_eq!(&bytes(entry.cbCredID, entry.pbCredID), id);
                        assert!(inside(entry.pHmacSecretSalt, &owned));
                        let salt = unsafe { &*entry.pHmacSecretSalt };
                        assert_eq!(salt.cbFirst, 32);
                        assert!(inside(salt.pbFirst, &owned));
                        assert_eq!(bytes(32, salt.pbFirst), first);
                        match second {
                            Some(second) => {
                                assert_eq!(salt.cbSecond, 32);
                                assert!(inside(salt.pbSecond, &owned));
                                assert_eq!(bytes(32, salt.pbSecond), second);
                            }
                            None => {
                                assert_eq!(salt.cbSecond, 0);
                                assert!(salt.pbSecond.is_null());
                            }
                        }
                    }
                    if o.dwVersion >= 8 {
                        assert_eq!(o.cCredentialHints, 1);
                        assert_eq!(text(unsafe { *o.ppwszCredentialHints }), "security-key");
                        assert!(inside(o.ppwszCredentialHints, &owned));
                    } else {
                        assert_eq!(o.cCredentialHints, 0);
                        assert!(o.ppwszCredentialHints.is_null());
                    }
                    assert_eq!(
                        (o.dwCredLargeBlobOperation, o.cbCredLargeBlob, o.bAutoFill),
                        (0, 0, 0)
                    );
                    assert!(o.pLinkedDevice.is_null() && o.pbJsonExt.is_null());
                    assert!(o.pwszRemoteWebOrigin.is_null() && o.pbAuthenticatorId.is_null());
                    assert_eq!(text(a.rp_id.as_ptr()), "goyo-vault.invalid");
                    assert!(inside(a.client.pbClientDataJSON, &owned));
                    assert_eq!(
                        bytes(a.client.cbClientDataJSON, a.client.pbClientDataJSON),
                        request.client_data
                    );
                    assert_eq!(text(a.client.pwszHashAlgId), "SHA-256");
                }
            }
        }
    }

    /// An assertion as Windows lays it out, over buffers this test owns.
    struct Answer {
        auth: Vec<u8>,
        cred: Vec<u8>,
        first: Vec<u8>,
        second: Vec<u8>,
        unsigned: Vec<u8>,
        client: Vec<u8>,
        response: Vec<u8>,
        salt: Box<HmacSalt>,
        assertion: Box<Assertion>,
    }
    fn answer(version: u32, transport: u32) -> Answer {
        let mut auth = [&fido::rp_id_hash()[..], &[fido::UP], &[0, 0, 0, 9]].concat();
        let mut cred = vec![7; 48];
        let mut first = vec![0x11; 32];
        let mut second = vec![0x22; 32];
        let mut unsigned = vec![0x33; 20];
        let mut client = vec![0x44; 30];
        let mut response = vec![0x55; 40];
        let salt = Box::new(HmacSalt {
            cbFirst: 32,
            pbFirst: first.as_mut_ptr(),
            cbSecond: 32,
            pbSecond: second.as_mut_ptr(),
        });
        let assertion = Box::new(Assertion {
            dwVersion: version,
            cbAuthenticatorData: auth.len() as u32,
            pbAuthenticatorData: auth.as_mut_ptr(),
            cbSignature: 0,
            pbSignature: null_mut(),
            Credential: Credential {
                dwVersion: 1,
                cbId: cred.len() as u32,
                pbId: cred.as_mut_ptr(),
                pwszCredentialType: null(),
            },
            cbUserId: 0,
            pbUserId: null_mut(),
            Extensions: Extensions {
                cExtensions: 0,
                pExtensions: null(),
            },
            cbCredLargeBlob: 0,
            pbCredLargeBlob: null_mut(),
            dwCredLargeBlobStatus: 0,
            pHmacSecret: &*salt as *const HmacSalt as *mut HmacSalt,
            dwUsedTransport: transport,
            cbUnsignedExtensionOutputs: unsigned.len() as u32,
            pbUnsignedExtensionOutputs: unsigned.as_mut_ptr(),
            cbClientDataJSON: client.len() as u32,
            pbClientDataJSON: client.as_mut_ptr(),
            cbAuthenticationResponseJSON: response.len() as u32,
            pbAuthenticationResponseJSON: response.as_mut_ptr(),
        });
        Answer {
            auth,
            cred,
            first,
            second,
            unsigned,
            client,
            response,
            salt,
            assertion,
        }
    }

    /// Windows' answers are read only up to their own version and the
    /// buffers that may hold the key's answer are zero when Windows frees
    /// them (spec §8.4, §14.8-3): a version-6 assertion, a version-4 one
    /// from a platform authenticator, and a version-3 one whose memory ends
    /// at a guard page right after its version-3 fields, which is taken
    /// with no transport and never read further.
    #[test]
    fn answers_are_read_to_their_version_and_wiped_before_free() {
        let mut a = answer(6, fido::USB);
        let p = &mut *a.assertion as *mut Assertion;
        let mut freed = false;
        let raw = unsafe {
            take_assertion(p, |q| {
                assert_eq!(q, p);
                freed = true;
            })
        };
        assert!(freed);
        assert_eq!(raw.version, 6);
        assert_eq!(raw.transport, Some(fido::USB));
        assert_eq!(raw.cred_id, a.cred);
        assert_eq!(raw.auth_data, a.auth);
        assert_eq!(
            raw.first.as_deref().map(Vec::as_slice),
            Some(&[0x11; 32][..])
        );
        assert_eq!(
            raw.second.as_deref().map(Vec::as_slice),
            Some(&[0x22; 32][..])
        );
        for wiped in [&a.first, &a.second, &a.unsigned, &a.client, &a.response] {
            assert!(wiped.iter().all(|b| *b == 0));
        }
        assert!(a.cred.iter().all(|b| *b == 7));
        let _ = &a.salt;
        // A checked answer at version 4: a platform authenticator is
        // refused, a USB key's answer taken with its transport.
        let request = AssertRequest::new(0, vec![(vec![7; 48], [1; 32], None)], false).unwrap();
        for (transport, ok) in [
            (fido::INTERNAL, false),
            (fido::HYBRID, false),
            (fido::NFC, true),
        ] {
            let mut a = answer(4, transport);
            let raw = unsafe { take_assertion(&mut *a.assertion, |_| {}) };
            let checked = check_assertion(raw, &request, false);
            assert_eq!(checked.is_ok(), ok, "{transport:#x}");
            if !ok {
                assert_eq!(checked.err(), Some(FidoError::Transport));
            }
            // Version 4 has no unsigned outputs or JSON: left as they are.
            assert!(a.first.iter().all(|b| *b == 0));
            assert!(a.unsigned.iter().all(|b| *b == 0x33));
        }

        // Version 3, ending at a page Windows would not let anyone read.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn VirtualAlloc(at: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
            fn VirtualProtect(at: *mut c_void, size: usize, protect: u32, old: *mut u32) -> i32;
            fn VirtualFree(at: *mut c_void, size: usize, kind: u32) -> i32;
        }
        let end = offset_of!(Assertion, dwUsedTransport);
        let full = answer(3, 0x99);
        unsafe {
            let pages = VirtualAlloc(null_mut(), 8192, 0x3000, 0x04);
            assert!(!pages.is_null());
            let mut old = 0;
            assert_ne!(
                VirtualProtect(pages.byte_add(4096), 4096, 0x01, &mut old),
                0
            );
            let at = pages.byte_add(4096 - end).cast::<u8>();
            std::ptr::copy_nonoverlapping(
                (&*full.assertion as *const Assertion).cast::<u8>(),
                at,
                end,
            );
            let p = at.cast::<Assertion>();
            let raw = take_assertion(p, |_| {});
            assert_eq!((raw.version, raw.transport), (3, None));
            assert_eq!(
                raw.first.as_deref().map(Vec::as_slice),
                Some(&[0x11; 32][..])
            );
            let touch = check_assertion(raw, &request, false).unwrap();
            assert_eq!(touch.transport, None);
            assert_ne!(VirtualFree(pages, 0, 0x8000), 0);
        }
        // A null second output, and an overlong first one, copied only far
        // enough to be refused.
        let mut a = answer(6, fido::USB);
        let mut long = vec![0x11; 100];
        a.salt.pbSecond = null();
        a.salt.pbFirst = long.as_mut_ptr();
        a.salt.cbFirst = 100;
        a.assertion.pHmacSecret = &mut *a.salt;
        let raw = unsafe { take_assertion(&mut *a.assertion, |_| {}) };
        assert_eq!(raw.first.as_ref().map(|f| f.len()), Some(OUTPUT_MAX));
        assert!(raw.second.is_none());
        assert_eq!(
            check_assertion(raw, &request, false).err(),
            Some(FidoError::BadAnswer)
        );
        assert!(long.iter().all(|b| *b == 0));
    }

    /// An attestation is read to its version, and its hmac-secret outputs
    /// (v7), unsigned outputs (v6) and JSON (v8) are zero when it is freed.
    #[test]
    fn attestations_are_read_to_their_version_and_wiped_before_free() {
        for version in [3, 6, 7, 8] {
            let mut auth = [&fido::rp_id_hash()[..], &[fido::UP | fido::AT]].concat();
            let mut cred = vec![9; 64];
            let mut first = vec![0x11; 32];
            let mut unsigned = vec![0x33; 8];
            let mut client = vec![0x44; 8];
            let mut response = vec![0x55; 8];
            let mut salt = HmacSalt {
                cbFirst: 32,
                pbFirst: first.as_mut_ptr(),
                cbSecond: 0,
                pbSecond: null(),
            };
            let mut a = CredentialAttestation {
                dwVersion: version,
                pwszFormatType: null(),
                cbAuthenticatorData: auth.len() as u32,
                pbAuthenticatorData: auth.as_mut_ptr(),
                cbAttestation: 0,
                pbAttestation: null_mut(),
                dwAttestationDecodeType: 0,
                pvAttestationDecode: null_mut(),
                cbAttestationObject: 0,
                pbAttestationObject: null_mut(),
                cbCredentialId: cred.len() as u32,
                pbCredentialId: cred.as_mut_ptr(),
                Extensions: Extensions {
                    cExtensions: 0,
                    pExtensions: null(),
                },
                dwUsedTransport: fido::NFC,
                bEpAtt: 0,
                bLargeBlobSupported: 0,
                bResidentKey: 1,
                bPrfEnabled: 1,
                cbUnsignedExtensionOutputs: unsigned.len() as u32,
                pbUnsignedExtensionOutputs: unsigned.as_mut_ptr(),
                pHmacSecret: &mut salt,
                bThirdPartyPayment: 0,
                dwTransports: 0,
                cbClientDataJSON: client.len() as u32,
                pbClientDataJSON: client.as_mut_ptr(),
                cbRegistrationResponseJSON: response.len() as u32,
                pbRegistrationResponseJSON: response.as_mut_ptr(),
            };
            let raw = unsafe { take_attestation(&mut a, |_| {}) };
            assert_eq!(
                (raw.version, raw.transport, &raw.cred_id, &raw.auth_data),
                (version, Some(fido::NFC), &cred, &auth)
            );
            assert_eq!(first.iter().all(|b| *b == 0), version >= 7);
            assert_eq!(unsigned.iter().all(|b| *b == 0), version >= 6);
            assert_eq!(client.iter().all(|b| *b == 0), version >= 8);
            assert_eq!(response.iter().all(|b| *b == 0), version >= 8);
        }
    }

    /// webauthn.dll loads from System32 with its nine exports, gives its
    /// API version and a cancel GUID, and a cancel with nothing running
    /// does nothing (spec §8.1, §8.5). No ceremony: nothing here opens a
    /// Windows dialog or needs a key.
    #[test]
    fn the_dll_loads_with_no_ceremony() {
        let Some(api) = api_version() else {
            return; // a Windows without it
        };
        let auth = match WebAuthn::load() {
            Ok(auth) => auth,
            Err(e) => {
                assert!(api < 4 && e == FidoError::NoApi);
                return;
            }
        };
        assert_eq!(auth.api_version(), api);
        let token = auth.new_cancel().unwrap();
        assert_ne!(token.id, [0; 16]);
        assert_ne!(auth.new_cancel().unwrap().id, token.id);
        auth.cancel(&token);
    }

    /// No call goes to Windows without the app's window as its owner: hWnd
    /// 0 fails at once, as Windows fails it (spec §2.28).
    #[test]
    fn no_call_is_made_without_an_owner_window() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Windows' exports, standing in: each call is counted and fails.
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "system" fn version() -> u32 {
            9
        }
        unsafe extern "system" fn make(
            _: Hwnd,
            _: *const RpEntity,
            _: *const UserEntity,
            _: *const CoseParams,
            _: *const ClientData,
            _: *const MakeCredOptions,
            _: *mut *mut CredentialAttestation,
        ) -> Hresult {
            CALLS.fetch_add(1, Ordering::SeqCst);
            fido::E_CANCELLED
        }
        unsafe extern "system" fn get(
            _: Hwnd,
            _: Pcwstr,
            _: *const ClientData,
            _: *const GetAssertionOptions,
            _: *mut *mut Assertion,
        ) -> Hresult {
            CALLS.fetch_add(1, Ordering::SeqCst);
            fido::E_CANCELLED
        }
        unsafe extern "system" fn free_attestation(_: *mut CredentialAttestation) {}
        unsafe extern "system" fn free_assertion(_: *mut Assertion) {}
        unsafe extern "system" fn cancel_id(_: *mut Guid) -> Hresult {
            0
        }
        unsafe extern "system" fn cancel(_: *const Guid) -> Hresult {
            0
        }
        unsafe extern "system" fn error_name(_: Hresult) -> Pcwstr {
            null()
        }
        unsafe extern "system" fn dom_error(hr: Hresult) -> Hresult {
            hr
        }
        static API: Api = Api {
            version,
            make,
            get,
            free_attestation,
            free_assertion,
            cancel_id,
            cancel,
            error_name,
            dom_error,
        };
        assert_eq!(owner_set(0), Err(FidoError::Rejected));
        assert_eq!(owner_set(0x1234), Ok(()));
        let auth = WebAuthn {
            api: &API,
            version: 9,
        };
        let token = CancelToken::new([1; 16]);
        for owner in [0, 0x1234] {
            let made = if owner == 0 {
                Some(FidoError::Rejected)
            } else {
                Some(FidoError::Cancelled)
            };
            let request = goyo_vault::fido::AssertRequest::new(
                owner,
                vec![(vec![1; 16], [2; 32], None)],
                true,
            )
            .unwrap();
            assert_eq!(auth.get_assertion(&request, &token).err(), made);
            let (_, make) =
                goyo_vault::fido::Registration::new(&[1; 16], 1, 0, vec![], owner).unwrap();
            assert_eq!(auth.make_credential(&make, &token).err(), made);
        }
        // Only the two calls with a window reached Windows.
        assert_eq!(CALLS.load(Ordering::SeqCst), 2);
    }

    /// Windows' codes become the app's errors (spec §8.7); its own text is
    /// never asked for.
    #[test]
    fn windows_codes_map_to_the_app_texts() {
        let other = 0x8009_0035_u32 as i32;
        assert_eq!(error_of(fido::E_CANCELLED, 0, None), FidoError::Cancelled);
        assert_eq!(
            error_of(fido::NTE_EXISTS, 0, Some(false)),
            FidoError::Exists
        );
        assert_eq!(
            error_of(other, fido::NTE_EXISTS, Some(true)),
            FidoError::Exists
        );
        assert_eq!(
            error_of(fido::STORE_FULL, 0, Some(false)),
            FidoError::StoreFull
        );
        // hWnd 0's code is a refused request, never a full store or a
        // missing extension, whatever DOM error Windows maps it to.
        for make in [None, Some(false), Some(true)] {
            for dom in [0, NTE_NOT_SUPPORTED, fido::E_CANCELLED] {
                assert_eq!(
                    error_of(fido::NTE_INVALID_PARAMETER, dom, make),
                    FidoError::Rejected
                );
            }
        }
        assert_eq!(
            error_of(NTE_NOT_SUPPORTED, 0, Some(true)),
            FidoError::NoCredProtect
        );
        assert_eq!(
            error_of(other, E_NOT_SUPPORTED, Some(false)),
            FidoError::NoHmacSecret
        );
        assert_eq!(
            error_of(other, fido::E_CANCELLED, None),
            FidoError::Cancelled
        );
        assert_eq!(
            error_of(NTE_NOT_SUPPORTED, 0, None),
            FidoError::Other(NTE_NOT_SUPPORTED)
        );
        assert_eq!(
            error_of(other, fido::NTE_EXISTS, None),
            FidoError::Other(other)
        );
        assert_eq!(error_of(other, other, Some(true)), FidoError::Other(other));
    }
}
