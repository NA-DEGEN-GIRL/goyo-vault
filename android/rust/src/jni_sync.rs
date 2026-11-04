//! The JNI entries of sync (stage 3, `app.goyovault.Native.sync*` and
//! `session*`). The engine runs (`syncRun`, `syncCheck`) take the client
//! key's seed as a byte array that the Kotlin side unwrapped from the
//! Keystore just before; it is copied into zeroized memory and the Java
//! array is zeroed, as a password is.
use crate::{
    bytes_out, hostkey, jerr, notice, run, ssh, string, syncrun, take_secret, text, with_session,
};
use goyo_vault::crypto;
use jni::{
    JNIEnv,
    objects::{JByteArray, JObject, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring},
};
use std::path::PathBuf;
use zeroize::Zeroizing;

fn paths(env: &mut JNIEnv, root: &JString) -> Result<syncrun::Paths, String> {
    Ok(syncrun::Paths::new(&PathBuf::from(string(env, root)?)))
}
/// A 32-byte ed25519 seed from a Java array (zeroed there), or None.
pub(crate) fn take_seed(
    env: &mut JNIEnv,
    a: &JByteArray,
) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    let Some(bytes) = take_secret(env, a)? else {
        return Ok(None);
    };
    if bytes.len() != 32 {
        return Err("동기화 키가 손상되었습니다. 설정에서 키를 다시 만드세요.".to_owned());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    Ok(Some(seed))
}
pub(crate) fn strings_out(env: &mut JNIEnv, items: &[&str]) -> Result<jobjectArray, String> {
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
fn shown_out(env: &mut JNIEnv, s: &syncrun::Shown) -> Result<jobjectArray, String> {
    strings_out(env, &[s.state, &s.text, &s.fingerprint])
}

/// `syncSettingsSave(root, host, port, user, remote, python)`: checks and
/// stores the settings; throws with the first bad field's text.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_goyovault_Native_syncSettingsSave<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    host: JString<'l>,
    port: JString<'l>,
    user: JString<'l>,
    remote: JString<'l>,
    python: JString<'l>,
) {
    run(&mut env, (), |env| {
        let paths = paths(env, &root)?;
        let settings = syncrun::Settings::new(
            &string(env, &host)?,
            &string(env, &port)?,
            &string(env, &user)?,
            &string(env, &remote)?,
            &string(env, &python)?,
        )?;
        syncrun::save_settings(&paths, &settings)
    })
}

/// `syncSettingsLoad(root)`: host, port, user, remote, python; or null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncSettingsLoad<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let paths = paths(env, &root)?;
        match syncrun::load_settings(&paths) {
            Some(s) => strings_out(
                env,
                &[&s.host, &s.port.to_string(), &s.user, &s.remote, &s.python],
            ),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `syncNewSeed()`: a new ed25519 seed from the lib's RNG, for Kotlin to
/// wrap with the Keystore key at once and zero.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncNewSeed<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let seed = crypto::random::<32>().map_err(str::to_owned)?;
        bytes_out(env, &seed[..])
    })
}

/// `syncPublic(seed)`: the base64 of the key's public wire encoding (what
/// follows `ssh-ed25519` in the line); the seed is zeroed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncPublic<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    seed: JByteArray<'l>,
) -> jstring {
    run(&mut env, std::ptr::null_mut(), |env| {
        let seed = take_seed(env, &seed)?.ok_or("키가 없습니다.")?;
        let blob = ssh::public_blob(&seed);
        Ok(env.new_string(blob).map_err(jerr)?.into_raw())
    })
}

/// `syncLine(root, blob, model)`: the authorized_keys line for this phone.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncLine<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    blob: JString<'l>,
    model: JString<'l>,
) -> jstring {
    run(&mut env, std::ptr::null_mut(), |env| {
        let paths = paths(env, &root)?;
        let line = syncrun::server_line(&paths, &string(env, &blob)?, &string(env, &model)?)?;
        Ok(env.new_string(line).map_err(jerr)?.into_raw())
    })
}

/// `syncRun(root, seed, force)`: one run of the engine (see syncrun.rs):
/// state, text, fingerprint. Never opens the vault.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncRun<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    seed: JByteArray<'l>,
    force: jboolean,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let seed = take_seed(env, &seed)?;
        let paths = paths(env, &root)?;
        let shown = syncrun::run(&paths, seed, force != 0);
        shown_out(env, &shown)
    })
}

/// `syncDue(root)`: whether a run would do anything now.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncDue<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
) -> jboolean {
    run(&mut env, 0, |env| {
        let paths = paths(env, &root)?;
        Ok(u8::from(syncrun::due(&paths)))
    })
}

/// `syncCheck(root, seed)`: '연결 확인' (HELLO and LIST).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncCheck<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    seed: JByteArray<'l>,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let seed = take_seed(env, &seed)?;
        let paths = paths(env, &root)?;
        let shown = syncrun::check(&paths, seed);
        shown_out(env, &shown)
    })
}

/// `syncLastResult(root)`: the last run's state, text, fingerprint; or null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncLastResult<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let paths = paths(env, &root)?;
        match syncrun::read_result(&paths) {
            Some(s) => shown_out(env, &s),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `syncPinHost(root, fingerprint)`: pins the host key the last unknown
/// host showed, if this is its fingerprint (what the user confirmed).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncPinHost<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    fingerprint: JString<'l>,
) {
    run(&mut env, (), |env| {
        let paths = paths(env, &root)?;
        syncrun::pin_offered(&paths, &string(env, &fingerprint)?)
    })
}

/// `syncPinned(root)`: `host:port` and the fingerprint of the pin, or null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncPinned<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let paths = paths(env, &root)?;
        match syncrun::load_pin(&paths) {
            Some(p) => strings_out(
                env,
                &[
                    &format!("{}:{}", p.host, p.port),
                    &hostkey::fingerprint(&p.blob),
                ],
            ),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `syncForgetPin(root)`: removes the pin (after the user's yes).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncForgetPin<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
) {
    run(&mut env, (), |env| {
        let paths = paths(env, &root)?;
        syncrun::forget_pin(&paths)
    })
}

/// `syncCancel()`: asks a running exchange to stop.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncCancel<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
) {
    run(&mut env, (), |_| {
        syncrun::cancel();
        Ok(())
    })
}

/// `syncReset(root)`: removes the vault's sync folder (a new import).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_syncReset<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
) {
    run(&mut env, (), |env| {
        let paths = paths(env, &root)?;
        syncrun::reset_folder(&paths);
        Ok(())
    })
}

/// `sessionSyncPoll(session)`: the open vault's `poll_sync` (merges a new
/// server copy, writes its upload, reads the status): the badge code, "1"
/// when the list changed, the notice's text, "1" when it is a warning.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_sessionSyncPoll<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let (badge, changed, line) = with_session(session, |s| {
            let event = s.poll_sync();
            let changed = event.as_ref().is_some_and(|e| e.list_changed);
            let line = event
                .and_then(|e| e.notice)
                .map(|n| notice::text(&n))
                .unwrap_or_default();
            Ok((notice::badge_code(s.badge()), changed, line))
        })?;
        strings_out(
            env,
            &[
                &badge.to_string(),
                if changed { "1" } else { "0" },
                &line.0,
                if line.1 { "1" } else { "0" },
            ],
        )
    })
}

/// `sessionUnlockNotice(session)`: the line after unlocking, once (text,
/// "1" when a warning); or null.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_sessionUnlockNotice<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let line = with_session(session, |s| {
            Ok(s.take_unlock_notice().map(|n| notice::text(&n)))
        })?;
        match line {
            Some((text, danger)) if !text.is_empty() => {
                strings_out(env, &[&text, if danger { "1" } else { "0" }])
            }
            _ => Ok(std::ptr::null_mut()),
        }
    })
}

/// `sessionBadge(session)`: see notice::badge_code.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_sessionBadge<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jint {
    run(&mut env, -1, |_| {
        with_session(session, |s| Ok(notice::badge_code(s.badge())))
    })
}

/// `sessionSyncOffer(session)`: whether to ask the user to turn sync on
/// for this vault (an older format, and the sync folder exists).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_sessionSyncOffer<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jboolean {
    run(&mut env, 0, |_| {
        with_session(session, |s| Ok(u8::from(s.sync_offer())))
    })
}

/// `sessionEnableSync(session)`: turns sync on after the user's yes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_sessionEnableSync<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) {
    run(&mut env, (), |_| {
        with_session(session, |s| s.enable_sync().map_err(text))
    })
}
