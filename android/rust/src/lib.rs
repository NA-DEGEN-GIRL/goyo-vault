//! The JNI bridge of the Android app (`app.goyovault.Native`): the app's
//! Kotlin code never sees a key, a derived secret or a vault file's
//! plaintext except the entry fields it shows. A login runs in two calls:
//! `prepare` reads the files and states the security-key request (the
//! allow list with each credential's salt, spec §8.3), Kotlin runs that one
//! assertion on the YubiKey (yubikit, USB or NFC) and hands back exactly
//! what the key returned, and `unlock` runs the core's own §8.4 checks on
//! it (rpIdHash, UP, UV, BE/BS, the credential asked for, the transport)
//! before the password and the hmac-secret output open the key file.
//!
//! Secrets cross as byte arrays: Rust copies a password or an hmac-secret
//! output into zeroized memory and then overwrites the Java array with
//! zeros; Kotlin zeroes its own copies too. Every entry point catches a
//! panic and throws `app.goyovault.GoyoException` with a Korean text.
#[cfg(test)]
mod engine_tests;
mod entry_otp;
mod fetch;
#[cfg(test)]
mod fetch_tests;
mod flows;
mod hostkey;
mod jni_keys;
mod jni_sync;
mod line;
mod notice;
mod reg;
mod ssh;
#[cfg(test)]
mod ssh_tests;
mod syncrun;
mod tailnet;
mod take;

use goyo_vault::{
    clock, crypto, fido,
    vault::{self, Entry, Prepared, Session, VaultClass},
};
use jni::{
    JNIEnv,
    objects::{JByteArray, JObject, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};
use zeroize::{Zeroize, Zeroizing};

const EXCEPTION: &str = "app/goyovault/GoyoException";
/// The request's wire format version (see `encode_request`).
const REQUEST_VERSION: u8 = 1;
/// Status bits of `status`.
const STATUS_TOFU: jint = 1;
const STATUS_GATE_PENDING: jint = 2;
/// The session's key file came from the server's key view and is not
/// saved on this device yet ("서버에서 가져온 금고", `fetchedSave`).
const STATUS_FETCHED: jint = 4;
/// Another device's key change waits to be taken with this unlock's touch
/// (`takeInfo`, `takePreview`, `takeAccept`).
const STATUS_TAKE: jint = 8;

/// A login between its two calls: the files as `prepare` read them and the
/// request the touch must answer (None: a key file without security keys).
/// `restore`: a vault from the server opened with the server's key file
/// (`prepareFetched`), restored in place.
struct Pending {
    prepared: Prepared,
    request: Option<fido::AssertRequest>,
    restore: Option<PathBuf>,
}
enum Slot {
    Pending(Box<Pending>),
    Open(Box<Session>),
}
static SLOTS: Mutex<Option<HashMap<jlong, Slot>>> = Mutex::new(None);

fn slots() -> MutexGuard<'static, Option<HashMap<jlong, Slot>>> {
    // A panic while the lock was held leaves the map as it was: still usable.
    SLOTS.lock().unwrap_or_else(|e| e.into_inner())
}
/// A fresh positive handle that names no slot.
fn new_handle(map: &HashMap<jlong, Slot>) -> Result<jlong, String> {
    loop {
        let bytes = crypto::random::<8>().map_err(str::to_owned)?;
        let h = i64::from_le_bytes(*bytes) & i64::MAX;
        if h != 0 && !map.contains_key(&h) {
            return Ok(h);
        }
    }
}
fn insert(slot: Slot) -> Result<jlong, String> {
    let mut guard = slots();
    let map = guard.get_or_insert_with(HashMap::new);
    let h = new_handle(map)?;
    map.insert(h, slot);
    Ok(h)
}
/// Runs `f` on the open session `h`.
fn with_session<T>(
    h: jlong,
    f: impl FnOnce(&mut Session) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = slots();
    match guard.as_mut().and_then(|m| m.get_mut(&h)) {
        Some(Slot::Open(s)) => f(s),
        _ => Err(LOCKED.to_owned()),
    }
}
const LOCKED: &str = "금고가 잠겼습니다. 다시 여세요.";
const NOT_SUPPORTED_YET: &str = "이 상태의 금고는 아직 Android 앱에서 열 수 없습니다. PC의 고요 금고에서 먼저 연 뒤 다시 가져오세요.";

/// A core refusal as text, its `{…}` slots filled when the core kept values.
fn text(e: &'static str) -> String {
    let Some(values) = vault::refusal_values(e) else {
        return e.to_owned();
    };
    let mut out = String::new();
    let mut rest = e;
    let mut values = values.into_iter();
    while let Some(start) = rest.find('{') {
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        out.push_str(&rest[..start]);
        match values.next() {
            Some(v) => out.push_str(&v),
            None => out.push_str(&rest[start..start + end + 1]),
        }
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}
fn fido_text(e: fido::FidoError) -> String {
    match e {
        fido::FidoError::Other(hr) => format!("보안 키 작업 실패 (코드 0x{:08X}).", hr as u32),
        e => e.text().to_owned(),
    }
}

/// Runs one JNI entry: a returned error or a panic becomes a thrown
/// GoyoException, and the entry returns `default`.
fn run<'l, T>(
    env: &mut JNIEnv<'l>,
    default: T,
    f: impl FnOnce(&mut JNIEnv<'l>) -> Result<T, String>,
) -> T {
    let result = catch_unwind(AssertUnwindSafe(|| f(env)))
        .unwrap_or_else(|_| Err("내부 오류가 났습니다. 앱을 다시 시작하세요.".to_owned()));
    match result {
        Ok(v) => v,
        Err(msg) => {
            if !env.exception_check().unwrap_or(false) {
                let _ = env.throw_new(EXCEPTION, msg);
            }
            default
        }
    }
}
fn jerr(_: jni::errors::Error) -> String {
    "앱 내부 통신 오류".to_owned()
}
fn string(env: &mut JNIEnv, s: &JString) -> Result<String, String> {
    Ok(env.get_string(s).map_err(jerr)?.into())
}
/// Copies a Java byte array into zeroized memory and overwrites the Java
/// array with zeros. A null array is None.
fn take_secret(env: &mut JNIEnv, a: &JByteArray) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    if a.is_null() {
        return Ok(None);
    }
    let bytes = Zeroizing::new(env.convert_byte_array(a).map_err(jerr)?);
    let zeros = vec![0i8; bytes.len()];
    env.set_byte_array_region(a, 0, &zeros).map_err(jerr)?;
    Ok(Some(bytes))
}
/// UTF-8 text from a secret byte array, never copied on the way.
fn secret_text(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, String> {
    let mut bytes = bytes;
    let owned = std::mem::take(&mut *bytes);
    match String::from_utf8(owned) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err("글자를 읽을 수 없습니다(UTF-8).".to_owned())
        }
    }
}
fn bytes_out(env: &mut JNIEnv, b: &[u8]) -> Result<jbyteArray, String> {
    Ok(env.byte_array_from_slice(b).map_err(jerr)?.into_raw())
}

/// The request for Kotlin, big-endian:
/// version u8 | uv u8 (1 required) | rp id length u8 | rp id |
/// clientDataHash [32] | count u8 | per credential: id length u16 | id |
/// salt1 [32] | has salt2 u8 | salt2 [32] if it has one.
/// The salts are what the key gets as they are (hmac-secret, no hashing).
fn encode_request(r: &fido::AssertRequest) -> Result<Vec<u8>, String> {
    let rp = fido::RP_ID.as_bytes();
    let mut out = vec![
        REQUEST_VERSION,
        u8::from(r.uv == fido::Uv::Required),
        u8::try_from(rp.len()).map_err(|_| "rp")?,
    ];
    out.extend_from_slice(rp);
    out.extend_from_slice(&Sha256::digest(&r.client_data));
    out.push(u8::try_from(r.allow.len()).map_err(|_| "보안 키가 너무 많습니다.")?);
    for (id, salt1, salt2) in &r.allow {
        out.extend_from_slice(&u16::try_from(id.len()).map_err(|_| "cred")?.to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(salt1);
        match salt2 {
            Some(s) => {
                out.push(1);
                out.extend_from_slice(s);
            }
            None => out.push(0),
        }
    }
    Ok(out)
}

/// `setAnchorRoot(path)`: the app's private files folder, once per process,
/// before any vault opens (vault::set_anchor_root).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_setAnchorRoot<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    path: JString<'l>,
) {
    run(&mut env, (), |env| {
        let path = PathBuf::from(string(env, &path)?);
        vault::set_anchor_root(&path).map_err(str::to_owned)
    })
}

/// `selfTest()`: the lib's HKDF and security-key self tests and one draw
/// of the RNG; throws when any fails.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_selfTest<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
) {
    run(&mut env, (), |_| {
        crypto::self_test().map_err(str::to_owned)?;
        fido::self_test().map_err(str::to_owned)?;
        crypto::random::<32>().map_err(str::to_owned)?;
        Ok(())
    })
}

/// `vaultTag(path)`: the vault's public tag (its ID's first bytes), or null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_vaultTag<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    path: JString<'l>,
) -> jstring {
    run(&mut env, std::ptr::null_mut(), |env| {
        let path = PathBuf::from(string(env, &path)?);
        match vault::vault_tag(&path) {
            Some(tag) => Ok(env.new_string(tag).map_err(jerr)?.into_raw()),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `prepare(vaultPath, keyPath)`: phase 1 of a login (public checks, no
/// password). Returns the pending login's handle. An older vault file that
/// needs the user's yes (S-OLDER) is refused before any touch. A changed
/// key file that waits for its gate opens in gate-pending mode (read-only)
/// and the vault screen asks the gate (`gateInfo`, `gatePass`), as the
/// PC's [나중에] then [받기…] do.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_prepare<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    vault_path: JString<'l>,
    key_path: JString<'l>,
) -> jlong {
    run(&mut env, 0, |env| {
        let v = PathBuf::from(string(env, &vault_path)?);
        let k = PathBuf::from(string(env, &key_path)?);
        let prepared = vault::prepare(&v, &k).map_err(text)?;
        if matches!(prepared.check().vault, VaultClass::Older { .. }) {
            return Err(NOT_SUPPORTED_YET.to_owned());
        }
        let request = prepared.unlock_request(0);
        insert(Slot::Pending(Box::new(Pending {
            prepared,
            request,
            restore: None,
        })))
    })
}

/// `request(pending)`: the security-key request of a pending login (see
/// `encode_request`), or null when the key file needs no security key.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_request<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    pending: jlong,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let encoded = {
            let guard = slots();
            match guard.as_ref().and_then(|m| m.get(&pending)) {
                Some(Slot::Pending(p)) => p.request.as_ref().map(encode_request).transpose()?,
                _ => return Err(LOCKED.to_owned()),
            }
        };
        match encoded {
            Some(bytes) => bytes_out(env, &bytes),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `unlock(pending, password, credId, authData, first, second, transport)`:
/// phase 3. The pending login is used up whatever happens. `password` is
/// UTF-8; it and the outputs are zeroed in the Java arrays. For a key file
/// with security keys, the assertion's fields are exactly what the key
/// returned (`second` null when it gave none, `transport` 1 USB or 2 NFC):
/// fido::check_assertion checks them against the request before anything
/// is derived. Returns the session's handle.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_goyovault_Native_unlock<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    pending: jlong,
    password: JByteArray<'l>,
    cred_id: JByteArray<'l>,
    auth_data: JByteArray<'l>,
    first: JByteArray<'l>,
    second: JByteArray<'l>,
    transport: jint,
) -> jlong {
    run(&mut env, 0, |env| {
        // Every secret leaves the Java arrays first, whatever fails next.
        let password = take_secret(env, &password)?;
        let first = take_secret(env, &first)?;
        let second = take_secret(env, &second)?;
        // Taken out under the lock, which is released at the end of this
        // statement: nothing below (the KDF above all) runs under it.
        let slot = slots().as_mut().and_then(|m| m.remove(&pending));
        let p = match slot {
            Some(Slot::Pending(p)) => p,
            Some(other) => {
                // Not a pending login: put it back untouched.
                slots()
                    .get_or_insert_with(HashMap::new)
                    .insert(pending, other);
                return Err(LOCKED.to_owned());
            }
            None => return Err(LOCKED.to_owned()),
        };
        let password = secret_text(password.ok_or("비밀번호를 입력하세요.")?)?;
        let Pending {
            prepared,
            request,
            restore,
        } = *p;
        let hint = prepared.auth_failure();
        let failed = |e: &'static str| {
            if e == crypto::AUTH_ERROR {
                text(hint.unwrap_or(e))
            } else {
                text(e)
            }
        };
        let session = match (request, &restore) {
            (None, None) => Session::login(prepared, &password, None).map_err(failed)?,
            (None, Some(v)) => Session::restore_from(prepared, v, &password).map_err(failed)?,
            (Some(request), restore) => {
                if first.is_none() || cred_id.is_null() || auth_data.is_null() {
                    return Err("보안 키 응답이 없습니다. YubiKey를 다시 대세요.".to_owned());
                }
                let raw = assertion_of(env, &cred_id, &auth_data, first, second, transport)?;
                let touch = fido::check_assertion(raw, &request, false).map_err(fido_text)?;
                if let Some(v) = restore {
                    Session::restore_with(prepared, v, &password, &touch).map_err(failed)?
                } else {
                    // The login that proves itself (spec §5.3): another
                    // device's key change waiting on the server may be
                    // taken with this unlock's password and touch.
                    let (session, proof) = Session::login_proved(prepared, &password, None, &touch)
                        .map_err(|f| failed(f.error))?;
                    let take = take::Take::offer(&session, proof, touch);
                    let h = insert(Slot::Open(Box::new(session)))?;
                    if let Some(take) = take {
                        jni_keys::set_take(h, take);
                    }
                    return Ok(h);
                }
            }
        };
        insert(Slot::Open(Box::new(session)))
    })
}

/// The transport a YubiKey answered over: 1 USB, 2 NFC.
fn transport_of(transport: jint) -> Result<u32, String> {
    match u32::try_from(transport) {
        Ok(t @ (fido::USB | fido::NFC)) => Ok(t),
        _ => Err(fido_text(fido::FidoError::Transport)),
    }
}
/// What a GetAssertion returned, as the core reads it: version 4 states
/// its transport, which check_assertion then holds to USB or NFC. The
/// outputs are already out of the Java arrays.
fn assertion_of(
    env: &mut JNIEnv,
    cred_id: &JByteArray,
    auth_data: &JByteArray,
    first: Option<Zeroizing<Vec<u8>>>,
    second: Option<Zeroizing<Vec<u8>>>,
    transport: jint,
) -> Result<fido::RawAssertion, String> {
    let transport = transport_of(transport)?;
    Ok(fido::RawAssertion {
        version: 4,
        auth_data: env.convert_byte_array(auth_data).map_err(jerr)?,
        cred_id: env.convert_byte_array(cred_id).map_err(jerr)?,
        first,
        second,
        transport: Some(transport),
    })
}
/// The same from the Java arrays of one JNI call (the outputs zeroed
/// there first, whatever fails next).
fn raw_assertion(
    env: &mut JNIEnv,
    cred_id: &JByteArray,
    auth_data: &JByteArray,
    first: &JByteArray,
    second: &JByteArray,
    transport: jint,
) -> Result<fido::RawAssertion, String> {
    let first = take_secret(env, first)?;
    let second = take_secret(env, second)?;
    if first.is_none() || cred_id.is_null() || auth_data.is_null() {
        return Err("보안 키 응답이 없습니다. YubiKey를 다시 대세요.".to_owned());
    }
    assertion_of(env, cred_id, auth_data, first, second, transport)
}

/// `discard(handle)`: drops a pending login, or locks a session.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_close<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    handle: jlong,
) {
    run(&mut env, (), |_| {
        jni_keys::drop_flows_of(handle);
        let slot = slots().as_mut().and_then(|m| m.remove(&handle));
        if let Some(Slot::Open(mut s)) = slot {
            s.before_lock();
        }
        Ok(())
    })
}

/// `closeAll()`: locks every session and drops every pending login (the
/// app went to the background or timed out).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_closeAll<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
) {
    run(&mut env, (), |_| {
        jni_keys::drop_flows();
        let all = slots().take();
        for (_, slot) in all.into_iter().flatten() {
            if let Slot::Open(mut s) = slot {
                s.before_lock();
            }
        }
        Ok(())
    })
}

/// `status(session)`: STATUS_TOFU (this device never confirmed the key
/// file's state: read-only until the code another device shows is typed)
/// and STATUS_GATE_PENDING.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_status<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jint {
    run(&mut env, 0, |_| {
        with_session(session, |s| {
            let mut bits = 0;
            if s.tofu() {
                bits |= STATUS_TOFU;
            }
            if s.gate_pending() {
                bits |= STATUS_GATE_PENDING;
            }
            if s.fetched_unsaved() {
                bits |= STATUS_FETCHED;
            }
            Ok(bits)
        })
        .map(|bits| {
            if jni_keys::has_take(session) {
                bits | STATUS_TAKE
            } else {
                bits
            }
        })
    })
}

/// `tofuConfirm(session, code)`: confirms the key file's state on this
/// device with the code the PC shows for it (S-TOFU), or, with a null
/// code, without one after the user's yes to S-TOFU-NOPC (the only way for
/// a 0.8 key file, which has no code).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_tofuConfirm<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    code: JString<'l>,
) {
    run(&mut env, (), |env| {
        if code.is_null() {
            return with_session(session, |s| s.tofu_confirm(None).map_err(text));
        }
        let typed = Zeroizing::new(string(env, &code)?);
        let code = vault::parse_code(&typed).ok_or("코드 형식이 맞지 않습니다.")?;
        with_session(session, |s| s.tofu_confirm(Some(&code)).map_err(text))
    })
}

/// `titles(session)`: title and kind of every entry, interleaved
/// (title 0, kind 0, title 1, ...). Never the secret or the notes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_titles<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let pairs: Vec<(String, String)> = with_session(session, |s| {
            Ok(s.entries
                .iter()
                .map(|e| (e.title.as_str().to_owned(), e.kind.as_str().to_owned()))
                .collect())
        })?;
        let len = jint::try_from(pairs.len() * 2).map_err(|_| "too many")?;
        let arr = env
            .new_object_array(len, "java/lang/String", JObject::null())
            .map_err(jerr)?;
        for (i, (title, kind)) in pairs.iter().enumerate() {
            let t = env.new_string(title).map_err(jerr)?;
            env.set_object_array_element(&arr, (2 * i) as jint, &t)
                .map_err(jerr)?;
            let k = env.new_string(kind).map_err(jerr)?;
            env.set_object_array_element(&arr, (2 * i + 1) as jint, &k)
                .map_err(jerr)?;
            env.delete_local_ref(t).map_err(jerr)?;
            env.delete_local_ref(k).map_err(jerr)?;
        }
        Ok(arr.into_raw())
    })
}

/// `field(session, index, which)`: one field of one entry as UTF-8 bytes
/// (0 title, 1 kind, 2 secret, 3 notes); Kotlin zeroes the array after use.
/// An OTP entry's secret is empty: its field (the marker, or 0.12.0's
/// dummy) never leaves Rust.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_field<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
    which: jint,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let value: Zeroizing<Vec<u8>> = with_session(session, |s| {
            let e = usize::try_from(index)
                .ok()
                .and_then(|i| s.entries.get(i))
                .ok_or("항목이 없습니다.")?;
            let field = match which {
                0 => e.title.as_str(),
                1 => e.kind.as_str(),
                2 => entry_otp::shown_secret(e),
                3 => e.notes.as_str(),
                _ => return Err("항목이 없습니다.".to_owned()),
            };
            Ok(Zeroizing::new(field.as_bytes().to_vec()))
        })?;
        bytes_out(env, &value)
    })
}

/// `put(session, index, title, kind, secret, notes, otp, removeOtp)`:
/// stores a new entry (index -1) or replaces entry `index`, and saves the
/// vault file. Every field is UTF-8 and zeroed in its Java array. `otp` is
/// the editor's OTP field (a Base32 key or an otpauth URI, parsed here);
/// null or empty keeps the edited entry's OTP secret, which the editor
/// never saw, or drops it when `removeOtp`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_goyovault_Native_put<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
    title: JByteArray<'l>,
    kind: JByteArray<'l>,
    secret: JByteArray<'l>,
    notes: JByteArray<'l>,
    otp: JByteArray<'l>,
    remove_otp: jboolean,
) {
    run(&mut env, (), |env| {
        let mut fields = Vec::with_capacity(5);
        for a in [&title, &kind, &secret, &notes, &otp] {
            let bytes = take_secret(env, a)?.unwrap_or_default();
            fields.push(secret_text(bytes)?);
        }
        let take = |z: &mut Zeroizing<String>| std::mem::take(&mut **z);
        let index = if index < 0 {
            None
        } else {
            Some(usize::try_from(index).map_err(|_| "항목이 없습니다.")?)
        };
        with_session(session, |s| {
            let old = match index {
                Some(i) => Some(s.entries.get(i).ok_or("항목이 없습니다.")?),
                None => None,
            };
            let entry = entry_otp::edited(
                old,
                [
                    take(&mut fields[0]),
                    take(&mut fields[1]),
                    take(&mut fields[2]),
                    take(&mut fields[3]),
                ],
                &fields[4],
                remove_otp != 0,
            )
            .map_err(text)?;
            s.put(index, entry).map_err(text)
        })
    })
}

/// Runs `f` on entry `index` of the open session `session`.
fn with_entry<T>(
    session: jlong,
    index: jint,
    f: impl FnOnce(&Entry) -> Result<T, &'static str>,
) -> Result<T, String> {
    with_session(session, |s| {
        let e = usize::try_from(index)
            .ok()
            .and_then(|i| s.entries.get(i))
            .ok_or("항목이 없습니다.")?;
        f(e).map_err(text)
    })
}
fn strings_out(env: &mut JNIEnv, items: &[&str]) -> Result<jobjectArray, String> {
    let len = jint::try_from(items.len()).map_err(|_| "too many")?;
    let arr = env
        .new_object_array(len, "java/lang/String", JObject::null())
        .map_err(jerr)?;
    for (i, item) in items.iter().enumerate() {
        let s = env.new_string(item).map_err(jerr)?;
        env.set_object_array_element(&arr, i as jint, &s)
            .map_err(jerr)?;
        env.delete_local_ref(s).map_err(jerr)?;
    }
    Ok(arr.into_raw())
}

/// `otpEntry(session, index)`: whether entry `index` is an OTP entry
/// (0.12.1), shown without 비밀정보.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_otpEntry<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
) -> jboolean {
    run(&mut env, 0, |_| {
        with_entry(session, index, |e| Ok(u8::from(e.is_otp_entry())))
    })
}

/// `isOtpKind(kind)`: whether the editor's kind is the OTP kind, by the
/// lib's own rule, so the editor's shape matches what saving does.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_isOtpKind<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    kind: JString<'l>,
) -> jboolean {
    run(&mut env, 0, |env| {
        Ok(u8::from(vault::is_otp_kind(&string(env, &kind)?)))
    })
}

/// `otpInfo(session, index)`: issuer, account and the code's settings when
/// they are not the usual ones (else ""), or null for an entry without an
/// OTP secret. Never the secret.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_otpInfo<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        match with_entry(session, index, |e| Ok(entry_otp::info(e)))? {
            Some(info) => strings_out(env, &[&info[0], &info[1], &info[2]]),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `otpCode(session, index)`: the code of this moment (made here from the
/// device clock) and the seconds until it changes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_otpCode<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let now = clock::now().map_err(str::to_owned)?;
        let (code, left) = with_entry(session, index, |e| entry_otp::code(e, now))?;
        strings_out(env, &[&code, &left.to_string()])
    })
}

/// `otpSecret(session, index)`: the OTP secret in Base32 as UTF-8, only for
/// the user's "시크릿 복사"; Kotlin zeroes the array after use.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_otpSecret<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let secret = with_entry(session, index, entry_otp::secret)?;
        bytes_out(env, secret.as_bytes())
    })
}

/// `otpQr(session, index)`: the QR code of the entry's otpauth URI, only
/// for the user's "QR 보기": side in modules (u16 big-endian), then one
/// byte per module, row-major, 1 dark. Kotlin zeroes the array once it
/// drew the bitmap.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_otpQr<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let modules = with_entry(session, index, entry_otp::qr_modules)?;
        bytes_out(env, &modules)
    })
}

/// `delete(session, index)`: deletes entry `index` and saves.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_delete<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    index: jint,
) {
    run(&mut env, (), |_| {
        let i = usize::try_from(index).map_err(|_| "항목이 없습니다.")?;
        with_session(session, |s| {
            if i >= s.entries.len() {
                return Err("항목이 없습니다.".to_owned());
            }
            s.delete(i).map_err(text)
        })
    })
}
