//! The JNI entries of stage 4 (`app.goyovault.Native`): a new vault, the
//! Keys screen (the keys, the key code, [키 추가], the key backup), the
//! gate of a changed key file (G1 code, G2 pick), "서버에서 가져오기" (the
//! server list and fetch) and the vault from the server ("서버에서 가져온
//! 금고": its unlock is `prepareFetched` with the usual `unlock`, then
//! `fetchedSave` after the other device's code or the trust without one).
use crate::{
    LOCKED, Pending, Slot, bytes_out, encode_request,
    flows::{Adding, Creating, Flow},
    insert, jerr, jni_sync, raw_assertion, run, secret_text, string, syncrun,
    take::{Need, Take},
    take_secret, text, with_session,
};
use goyo_vault::vault::{self, GateAnswer, GateKind, Prepared};
use jni::{
    JNIEnv,
    objects::{JByteArray, JIntArray, JObject, JString},
    sys::{jboolean, jbyteArray, jint, jlong, jobjectArray, jstring},
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroizing;

static FLOWS: Mutex<Option<HashMap<jlong, Flow>>> = Mutex::new(None);
fn flows() -> MutexGuard<'static, Option<HashMap<jlong, Flow>>> {
    FLOWS.lock().unwrap_or_else(|e| e.into_inner())
}
fn new_flow(flow: Flow) -> Result<jlong, String> {
    let mut guard = flows();
    let map = guard.get_or_insert_with(HashMap::new);
    loop {
        let bytes = goyo_vault::crypto::random::<8>().map_err(str::to_owned)?;
        let h = i64::from_le_bytes(*bytes) & i64::MAX;
        if h != 0 && !map.contains_key(&h) {
            map.insert(h, flow);
            return Ok(h);
        }
    }
}
/// Takes flow `h` out of the map for one step (no lock is held while the
/// step runs, which may derive a key); `put_back` returns it.
fn take_flow(h: jlong) -> Result<Flow, String> {
    flows()
        .as_mut()
        .and_then(|m| m.remove(&h))
        .ok_or_else(|| "작업이 끝났거나 잠겼습니다. 처음부터 다시 하세요.".to_owned())
}
fn put_back(h: jlong, flow: Flow) {
    flows().get_or_insert_with(HashMap::new).insert(h, flow);
}
/// Drops every flow and take (a lock): their secrets are zeroized on drop.
pub fn drop_flows() {
    let all = flows().take();
    drop(all);
    let takes = takes().take();
    drop(takes);
}
/// Drops the flows and the take of `session` (it was closed).
pub fn drop_flows_of(session: jlong) {
    if let Some(map) = flows().as_mut() {
        map.retain(|_, f| !matches!(f, Flow::AddKey(a) if a.session == session));
    }
    let take = takes().as_mut().and_then(|m| m.remove(&session));
    drop(take);
}

/// Another device's key change offered at unlock, by session.
static TAKES: Mutex<Option<HashMap<jlong, Take>>> = Mutex::new(None);
fn takes() -> MutexGuard<'static, Option<HashMap<jlong, Take>>> {
    TAKES.lock().unwrap_or_else(|e| e.into_inner())
}
pub fn set_take(session: jlong, take: Take) {
    takes()
        .get_or_insert_with(HashMap::new)
        .insert(session, take);
}
pub fn has_take(session: jlong) -> bool {
    takes().as_ref().is_some_and(|m| m.contains_key(&session))
}
fn take_out(session: jlong) -> Result<Take, String> {
    takes()
        .as_mut()
        .and_then(|m| m.remove(&session))
        .ok_or_else(|| "받을 열쇠 변경이 없습니다. 금고를 다시 여세요.".to_owned())
}
fn password_of(env: &mut JNIEnv, a: &JByteArray) -> Result<Zeroizing<String>, String> {
    secret_text(take_secret(env, a)?.ok_or("비밀번호를 입력하세요.")?)
}
fn strings(env: &mut JNIEnv, items: &[String]) -> Result<jobjectArray, String> {
    let refs: Vec<&str> = items.iter().map(String::as_str).collect();
    jni_sync::strings_out(env, &refs)
}

// ---- a new vault ----

/// `passwordCheck(password)`: the PC's password policy; throws its text.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_passwordCheck<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    password: JByteArray<'l>,
) {
    run(&mut env, (), |env| {
        let password = password_of(env, &password)?;
        vault::password_policy(&password).map_err(text)
    })
}

/// `createBegin(password)`: a new vault's flow (its ID and data key drawn,
/// the password checked and kept in Rust); the flow's handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_createBegin<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    password: JByteArray<'l>,
) -> jlong {
    run(&mut env, 0, |env| {
        let password = password_of(env, &password)?;
        new_flow(Flow::Create(Box::new(Creating::new(password)?)))
    })
}

/// `createTag(flow)`: the new vault's tag.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_createTag<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
) -> jstring {
    run(&mut env, std::ptr::null_mut(), |env| {
        let tag = match flows().as_ref().and_then(|m| m.get(&flow)) {
            Some(Flow::Create(c)) => c.tag(),
            _ => return Err(LOCKED.to_owned()),
        };
        Ok(env.new_string(tag).map_err(jerr)?.into_raw())
    })
}

/// `createFinish(flow, vaultPath, keyPath, withKeys)`: writes the new vault
/// (with the keys registered, or password-only) and returns its session.
/// The flow is used up.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_createFinish<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
    vault_path: JString<'l>,
    key_path: JString<'l>,
    with_keys: jboolean,
) -> jlong {
    run(&mut env, 0, |env| {
        let v = PathBuf::from(string(env, &vault_path)?);
        let k = PathBuf::from(string(env, &key_path)?);
        let Flow::Create(c) = take_flow(flow)? else {
            return Err(LOCKED.to_owned());
        };
        let session = c.finish(&v, &k, with_keys != 0)?;
        insert(Slot::Open(Box::new(session)))
    })
}

/// `flowClose(flow)`: drops a flow (cancelled).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_flowClose<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
) {
    run(&mut env, (), |_| {
        let _ = take_flow(flow);
        Ok(())
    })
}

// ---- registrations (a new vault's keys, [키 추가]) ----

/// `regStart(flow)`: the next registration's MakeCredential request (see
/// reg::encode_make).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_regStart<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let mut f = take_flow(flow)?;
        let wire = f.register();
        put_back(flow, f);
        bytes_out(env, &wire?)
    })
}

/// `regMade(flow, authData, transport)`: MakeCredential's authenticator
/// data as the key returned it; the check GetAssertion's request (as
/// `request`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_regMade<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
    auth_data: JByteArray<'l>,
    transport: jint,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let data = env.convert_byte_array(&auth_data).map_err(jerr)?;
        let transport = crate::transport_of(transport)?;
        let mut f = take_flow(flow)?;
        let check = f.made(&data, transport);
        put_back(flow, f);
        bytes_out(env, &encode_request(&check?)?)
    })
}

/// `regChecked(flow, credId, authData, first, second, transport)`: the
/// check's answer (the outputs zeroed in the Java arrays); the number of
/// keys the flow holds now.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_goyovault_Native_regChecked<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
    cred_id: JByteArray<'l>,
    auth_data: JByteArray<'l>,
    first: JByteArray<'l>,
    second: JByteArray<'l>,
    transport: jint,
) -> jint {
    run(&mut env, 0, |env| {
        let raw = raw_assertion(env, &cred_id, &auth_data, &first, &second, transport)?;
        let mut f = take_flow(flow)?;
        let n = f.checked(raw);
        put_back(flow, f);
        Ok(jint::try_from(n?).unwrap_or(0))
    })
}

// ---- the Keys screen ----

/// `keyAddGate(session)`: the question of what holds a key change now
/// (default no), or null; throws when it cannot be overridden.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_keyAddGate<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jstring {
    run(&mut env, std::ptr::null_mut(), |env| {
        match with_session(session, crate::flows::gate)? {
            Some(q) => Ok(env.new_string(text(q)).map_err(jerr)?.into_raw()),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `keyAddBegin(session, password, overrideGate)`: [키 추가]'s flow; its
/// touch request (a key that reaches every other) is `flowTouchRequest`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_keyAddBegin<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    password: JByteArray<'l>,
    override_gate: jboolean,
) -> jlong {
    run(&mut env, 0, |env| {
        let password = password_of(env, &password)?;
        let adding = with_session(session, |s| {
            Adding::new(s, session, password, override_gate != 0)
        })?;
        new_flow(Flow::AddKey(Box::new(adding)))
    })
}

/// `flowTouchRequest(flow)`: the Reauth touch's request (as `request`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_flowTouchRequest<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
) -> jbyteArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let wire = match flows().as_ref().and_then(|m| m.get(&flow)) {
            Some(Flow::AddKey(a)) => encode_request(a.touch_request())?,
            _ => return Err(LOCKED.to_owned()),
        };
        bytes_out(env, &wire)
    })
}

/// `keyAddReauth(flow, credId, authData, first, second, transport)`: the
/// Reauth with the flow's password and this touch.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_app_goyovault_Native_keyAddReauth<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
    cred_id: JByteArray<'l>,
    auth_data: JByteArray<'l>,
    first: JByteArray<'l>,
    second: JByteArray<'l>,
    transport: jint,
) {
    run(&mut env, (), |env| {
        let raw = raw_assertion(env, &cred_id, &auth_data, &first, &second, transport)?;
        let Flow::AddKey(mut a) = take_flow(flow)? else {
            return Err(LOCKED.to_owned());
        };
        let session = a.session;
        let result = with_session(session, |s| a.reauth(s, raw));
        if result.is_ok() {
            put_back(flow, Flow::AddKey(a));
        }
        result
    })
}

/// `keyAddFinish(flow)`: the write; the text to show, and "1" when the app
/// must lock now (S-GAP-CHANGED). The flow is used up.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_keyAddFinish<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    flow: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let Flow::AddKey(a) = take_flow(flow)? else {
            return Err(LOCKED.to_owned());
        };
        let (line, lock) = with_session(a.session, |s| a.finish(s))?;
        strings(env, &[line, if lock { "1" } else { "0" }.to_owned()])
    })
}

/// A registration's day, YYYY-MM-DD, from its `<STAMP>`.
fn day(stamp: &str) -> String {
    match (stamp.get(..4), stamp.get(4..6), stamp.get(6..8)) {
        (Some(y), Some(m), Some(d)) => format!("{y}-{m}-{d}"),
        _ => String::new(),
    }
}
fn listed(numbers: &[u8]) -> String {
    numbers
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
/// What the Keys screen shows (spec §9.1): the state line, the key code
/// (or "" before the key file is confirmed), "1" when the key file has no
/// backup yet, the line of the keys that reach every other, then one row
/// per key.
pub fn keys_lines(s: &vault::Session) -> Vec<String> {
    let mut out = Vec::new();
    let o = s.keys_overview();
    out.push(match &o {
        None => "보안 키: 꺼짐".to_owned(),
        Some(o) if o.pin => format!("보안 키: 켜짐 · PIN 사용 · {}개 등록", o.rows.len()),
        Some(o) => format!("보안 키: 켜짐 · {}개 등록", o.rows.len()),
    });
    out.push(s.key_code().unwrap_or_default());
    out.push(if s.key_backup_due() { "1" } else { "0" }.to_owned());
    match &o {
        None => out.push(String::new()),
        Some(o) if o.full.is_empty() => out
            .push("다른 키를 모두 대신할 수 있는 키: 없음 (PC에서 '짝 맺기'를 하세요)".to_owned()),
        Some(o) => out.push(format!(
            "다른 키를 모두 대신할 수 있는 키: 보안 키 {}",
            listed(&o.full)
        )),
    }
    for r in o.iter().flat_map(|o| o.rows.iter()) {
        let mut parts = vec![format!("보안 키 {} · {} 등록", r.number, day(&r.stamp))];
        if r.opened {
            parts.push("이번에 연 키".to_owned());
        }
        if r.orphan {
            parts.push("짝 기록 없음: 빼고 다시 등록해야 함".to_owned());
        } else if r.suspended {
            parts.push("일시 정지(짝 맺기 필요)".to_owned());
        } else if !r.broken.is_empty() {
            parts.push(format!(
                "짝 기록 손상: 보안 키 {}과(와) 다시 짝 맺기 필요",
                listed(&r.broken)
            ));
        } else if !r.unpaired.is_empty() {
            parts.push(format!(
                "보안 키 {}과(와) 짝 맺기 필요",
                listed(&r.unpaired)
            ));
        } else {
            parts.push("모든 키와 짝".to_owned());
        }
        if r.cloned {
            parts.push("복제됐을 수 있음: 모든 키 새로 잠그기나 다시 등록 권장".to_owned());
        }
        out.push(parts.join(" · "));
    }
    out
}

/// `keysInfo(session)`: see keys_lines.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_keysInfo<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let lines = with_session(session, |s| Ok(keys_lines(s)))?;
        strings(env, &lines)
    })
}

/// `keyBackup(session, path)`: a copy of the key file at `path` (a new
/// file in the app's cache that Kotlin copies to the place the user picked
/// and deletes), read back and recorded as backed up.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_keyBackup<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    path: JString<'l>,
) {
    run(&mut env, (), |env| {
        let path = PathBuf::from(string(env, &path)?);
        with_session(session, |s| s.backup_key(&path).map_err(text))
    })
}

// ---- the gate of a changed key file (gate-pending mode) ----

/// `gateInfo(session)`: "G1" or "G2", the key file's epoch, then for G2
/// each of this device's keys as "number|YYYY-MM-DD" (from the anchor's
/// confirmed state only, never the changed file); null when no gate waits.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_gateInfo<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let lines = with_session(session, |s| {
            let Some(kind) = s.login_gate() else {
                return Ok(None);
            };
            let mut out = vec![
                match kind {
                    GateKind::G1 => "G1",
                    GateKind::G2 => "G2",
                }
                .to_owned(),
                s.key_state().epoch.to_string(),
            ];
            if kind == GateKind::G2 {
                for c in s.gate_choices() {
                    let date = std::str::from_utf8(&c.date).unwrap_or("");
                    let opened = s.unlocked_with() == Some(c.number);
                    out.push(format!(
                        "{}|{}{}",
                        c.number,
                        day(date),
                        if opened { "|1" } else { "" }
                    ));
                }
            }
            Ok(Some(out))
        })?;
        match lines {
            Some(lines) => strings(env, &lines),
            None => Ok(std::ptr::null_mut()),
        }
    })
}

/// `gatePass(session, code, picks)`: the gate's answer: the other device's
/// key code (G1), or the keys picked as lost (G2, this device's numbers).
/// A wrong pick turns G2 off (the next answer is a code); a wrong code may
/// be typed again.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_gatePass<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    code: JString<'l>,
    picks: JIntArray<'l>,
) {
    run(&mut env, (), |env| {
        if !code.is_null() {
            let typed = Zeroizing::new(string(env, &code)?);
            let code = vault::parse_code(&typed).ok_or("코드 형식이 맞지 않습니다.")?;
            return with_session(session, |s| {
                s.pass_login_gate(GateAnswer::Code(code)).map_err(text)
            });
        }
        if picks.is_null() {
            return Err("코드를 입력하거나 잃어버린 키를 고르세요.".into());
        }
        let n = env.get_array_length(&picks).map_err(jerr)?;
        let mut numbers = vec![0; usize::try_from(n).unwrap_or(0)];
        env.get_int_array_region(&picks, 0, &mut numbers)
            .map_err(jerr)?;
        with_session(session, |s| {
            let pick = pick_of(&s.gate_choices(), &numbers)?;
            s.pass_login_gate(GateAnswer::Pick(pick)).map_err(text)
        })
    })
}

/// The credhashes of the keys numbered `numbers` among `choices` (this
/// device's own keys, as S-LOSTPICK lists them); none twice, at least one.
pub fn pick_of(choices: &[vault::GateChoice], numbers: &[i32]) -> Result<Vec<[u8; 16]>, String> {
    let mut pick = Vec::with_capacity(numbers.len());
    for n in numbers {
        let c = choices
            .iter()
            .find(|c| i32::from(c.number) == *n)
            .ok_or("고른 키가 목록에 없습니다.")?;
        if pick.contains(&c.credhash) {
            return Err("같은 키를 두 번 골랐습니다.".into());
        }
        pick.push(c.credhash);
    }
    if pick.is_empty() {
        return Err("잃어버린 키를 하나 이상 고르세요.".into());
    }
    Ok(pick)
}

// ---- "서버에서 가져오기" ----

fn paths(env: &mut JNIEnv, root: &JString) -> Result<syncrun::Paths, String> {
    Ok(syncrun::Paths::new(&PathBuf::from(string(env, root)?)))
}

/// `serverList(root, seed)`: the server's vaults, one row each as
/// "id|tag|head|size|mtime|key" (key: held, missing, notallowed, unknown).
/// The seed is zeroed. Throws with the reason when the exchange failed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_serverList<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    seed: JByteArray<'l>,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let seed = jni_sync::take_seed(env, &seed)?;
        let paths = paths(env, &root)?;
        let rows = syncrun::server_list(&paths, seed)?;
        let lines: Vec<String> = rows.iter().map(|r| r.join("|")).collect();
        strings(env, &lines)
    })
}

/// `serverFetch(root, seed, id)`: the head version of vault `id` as the
/// phone's vault file (none may be there), then its key file from the
/// server as the key view: version, size, key result (written, nokeys,
/// empty, bad, write, failed).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_serverFetch<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    seed: JByteArray<'l>,
    id: JString<'l>,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let seed = jni_sync::take_seed(env, &seed)?;
        let paths = paths(env, &root)?;
        let id =
            crate::fetch::parse_id(&string(env, &id)?).ok_or("금고 ID가 올바르지 않습니다.")?;
        let (version, bytes, key) = syncrun::server_fetch(&paths, seed, id)?;
        strings(
            env,
            &[version.to_string(), bytes.to_string(), key.to_owned()],
        )
    })
}

/// `fetchedState(vaultPath)`: 0 when the vault file has no key file from
/// the server in its sync folder, 1 when it has one that needs a security
/// key, 2 when it has one without.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_fetchedState<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    vault_path: JString<'l>,
) -> jint {
    run(&mut env, 0, |env| {
        let v = PathBuf::from(string(env, &vault_path)?);
        Ok(match vault::fetched_key_info(&v) {
            None => 0,
            Some(i) if i.needs_security_key => 1,
            Some(_) => 2,
        })
    })
}

/// `prepareFetched(vaultPath)`: phase 1 of opening a vault from the server
/// with the server's key file (`prepare_restore_fetched`: the vault file
/// is the floor, nothing is written outside the sync folder, read-only
/// until the code). The pending login's handle, for `request` and
/// `unlock` as usual.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_prepareFetched<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    vault_path: JString<'l>,
) -> jlong {
    run(&mut env, 0, |env| {
        let v = PathBuf::from(string(env, &vault_path)?);
        let prepared: Prepared = vault::prepare_restore_fetched(&v).map_err(text)?;
        let request = prepared.unlock_request(0);
        insert(Slot::Pending(Box::new(Pending {
            prepared,
            request,
            restore: Some(v),
        })))
    })
}

/// `fetchedSave(session, code, keyPath)`: the key file from the server,
/// confirmed with the other device's key code (G1), or with none after
/// the user's yes to the trust without a code (or when this device
/// confirmed that state before), written at `keyPath`; sync starts.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_fetchedSave<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    code: JString<'l>,
    key_path: JString<'l>,
) {
    run(&mut env, (), |env| {
        let path = PathBuf::from(string(env, &key_path)?);
        let code = if code.is_null() {
            None
        } else {
            let typed = Zeroizing::new(string(env, &code)?);
            Some(vault::parse_code(&typed).ok_or("코드 형식이 맞지 않습니다.")?)
        };
        with_session(session, |s| {
            s.tofu_check(code.as_ref()).map_err(text)?;
            s.tofu_save(code.as_ref(), &path).map_err(text)
        })
    })
}

// ---- another device's key change, taken at unlock ----

/// `takeInfo(session)`: what the waiting take needs: "none" (only
/// [받기]), "G1" (the other device's key code) or "G2" (the keys picked
/// as lost), the server file's epoch, then for G2 this device's keys as
/// "number|YYYY-MM-DD"; null when none waits.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_takeInfo<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let info = takes()
            .as_ref()
            .and_then(|m| m.get(&session))
            .map(|t| (t.need(), t.epoch()));
        let Some((need, epoch)) = info else {
            return Ok(std::ptr::null_mut());
        };
        let mut out = vec![
            match need {
                Need::Nothing => "none",
                Need::G1 => "G1",
                Need::G2 => "G2",
            }
            .to_owned(),
            epoch.to_string(),
        ];
        if need == Need::G2 {
            let choices = with_session(session, |s| Ok(s.gate_choices()))?;
            for c in choices {
                let date = std::str::from_utf8(&c.date).unwrap_or("");
                out.push(format!("{}|{}", c.number, day(date)));
            }
        }
        strings(env, &out)
    })
}

/// `takePreview(session, code, picks, otherPassword)`: the gate's answer
/// (a code for G1, this device's numbers of the lost keys for G2, both
/// null otherwise), the server's file opened (with the other device's new
/// password when it is given) and previewed: "needpass" when that password
/// is needed, else "ok" and the lines of what [받기] does. A wrong code may
/// be typed again.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_takePreview<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
    code: JString<'l>,
    picks: JIntArray<'l>,
    other_password: JByteArray<'l>,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let other = match take_secret(env, &other_password)? {
            Some(bytes) => Some(secret_text(bytes)?),
            None => None,
        };
        let answer = if !code.is_null() {
            let typed = Zeroizing::new(string(env, &code)?);
            Some(GateAnswer::Code(
                vault::parse_code(&typed).ok_or("코드 형식이 맞지 않습니다.")?,
            ))
        } else if !picks.is_null() {
            let n = env.get_array_length(&picks).map_err(jerr)?;
            let mut numbers = vec![0; usize::try_from(n).unwrap_or(0)];
            env.get_int_array_region(&picks, 0, &mut numbers)
                .map_err(jerr)?;
            let choices = with_session(session, |s| Ok(s.gate_choices()))?;
            Some(GateAnswer::Pick(pick_of(&choices, &numbers)?))
        } else {
            None
        };
        let mut take = take_out(session)?;
        let result = with_session(session, |s| {
            take.preview(s, answer, other.as_deref().map(|p| p.as_str()))
                .map_err(text)
        });
        // A wrong code or password may be tried again; the take stays
        // unless the session is gone.
        if !matches!(&result, Err(e) if e == LOCKED) {
            set_take(session, take);
        }
        let out = match result? {
            None => vec!["needpass".to_owned(), crate::take::NEWPASS_OTHER.to_owned()],
            Some(lines) => std::iter::once("ok".to_owned()).chain(lines).collect(),
        };
        strings(env, &out)
    })
}

/// `takeAccept(session)`: [받기] after `takePreview`: the write; the lines
/// to show, then "1" when the app must lock now.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_takeAccept<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) -> jobjectArray {
    run(&mut env, std::ptr::null_mut(), |env| {
        let take = take_out(session)?;
        let (mut lines, lock) = with_session(session, |s| take.accept(s).map_err(text))?;
        lines.push(if lock { "1" } else { "0" }.to_owned());
        strings(env, &lines)
    })
}

/// `takeDrop(session)`: [나중에]: nothing is taken; the next unlock offers
/// it again.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_takeDrop<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    session: jlong,
) {
    run(&mut env, (), |_| {
        let take = takes().as_mut().and_then(|m| m.remove(&session));
        drop(take);
        Ok(())
    })
}

/// `loginKeys(keyPath)`: the login note's keys (spec §9.1): -1 when the
/// file cannot be read, 0 for a password-only key file, else the number
/// of security keys (this device's confirmed state's for a changed file).
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_loginKeys<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    key_path: JString<'l>,
) -> jint {
    run(&mut env, -1, |env| {
        let k = PathBuf::from(string(env, &key_path)?);
        Ok(match vault::login_keys(&k) {
            None => -1,
            Some(vault::LoginKeys::PasswordOnly) => 0,
            Some(vault::LoginKeys::Keys { n, .. }) => jint::try_from(n).unwrap_or(1),
        })
    })
}

/// `serverFetchKey(root, seed)`: the server's key file of the phone's
/// vault (fetched before, or imported without a key file) into its sync
/// folder as the key view, as `serverFetch` does after the vault file.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_goyovault_Native_serverFetchKey<'l>(
    mut env: JNIEnv<'l>,
    _this: JObject<'l>,
    root: JString<'l>,
    seed: JByteArray<'l>,
) -> jstring {
    run(&mut env, std::ptr::null_mut(), |env| {
        let seed = jni_sync::take_seed(env, &seed)?;
        let paths = paths(env, &root)?;
        let word = syncrun::server_fetch_key(&paths, seed)?;
        Ok(env.new_string(word).map_err(jerr)?.into_raw())
    })
}
