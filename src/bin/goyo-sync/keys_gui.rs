//! The security-key build's words in goyo-sync's window (spec v3 §9.3): a
//! file only that build compiles, so the default exe carries none of them,
//! with their English in `i18n::EN_SK`.
use crate::{
    config::Config,
    engine::tag,
    i18n::{fill, tr},
    keysetup::{Key, Outcome, Plan},
    setup::{KeyGot, Live, ServerKey},
    syncfile,
};
use goyo_vault::syncfile::{
    FileError, INCOMING, INCOMING_MAGIC, KEY_REQUEST, KEY_VIEW, MAX_KEY_VIEW, RecordKind, Stamp,
    SyncState, parse_key_view, parse_record_header,
};
use std::{io::Read, path::Path};

/// The button under the vault list that shows the forced-command line.
pub const LINE_BUTTON: &str = "강제 명령 줄…";
/// Beside it: where key-file sync is switched, and why the line matters
/// (spec §2.29 (sync)). The switch is goyo-vault's alone.
pub const LINE_NOTE: &str = "열쇠 파일 동기화는 고요 금고의 '열쇠 관리'에서 켭니다. 금고를 넣거나 뺀 뒤에는 '서버에 설치·업데이트'를 다시 누르세요.";
/// The first paragraph of what [강제 명령 줄…] shows: the button above
/// does all of it (keysetup.rs); the line is for a server kept by hand.
pub const AUTO_LINE: &str = "'서버에 설치·업데이트'가 이 일을 자동으로 합니다: 이 PC 전용 키를 만들고(없을 때), 서버의 authorized_keys에 이 PC의 줄을 넣거나 바꾸고, goyo-sync.conf에 저장합니다. 서버를 직접 관리할 때만 아래처럼 하세요.";
/// The vaults `--key-sync` can name at most (spec v3 §7.13). The line
/// names only vaults in the settings list, which holds fewer, so none is
/// ever left out.
const MAX_IDS: usize = 64;
const _: () = assert!(crate::config::MAX_VAULTS <= MAX_IDS);
/// The script path or the Python command could close the line's quoted
/// command (a `"`, a `,`, a line break): no line is shown, as no install
/// command is run with them.
pub const UNSAFE_LINE: &str = "고급 설정의 스크립트 경로나 파이썬 명령에 쓸 수 없는 글자가 있어 강제 명령 줄을 만들지 않았습니다. 그 두 칸을 고친 뒤 다시 누르세요.";

/// The vault ID of a synced vault file (GOYOVA02 or GOYOVA04: bytes 8..24
/// of its header) and its flags byte (byte 64 of a GOYOVA04 file, else 0).
/// None for any other file. Only the first 65 bytes are read, and only
/// for the wording of the forced-command line: the header is not
/// authenticated before the vault app opens it.
pub fn vault_header(path: &Path) -> Option<([u8; 16], u8)> {
    let mut head = [0u8; 65];
    let mut file = std::fs::File::open(path).ok()?;
    let n = file.read(&mut head).ok()?;
    let keyed = n == head.len() && head.starts_with(b"GOYOVA04");
    let synced = keyed || (n >= 24 && head.starts_with(b"GOYOVA02"));
    let id: [u8; 16] = head[8..24].try_into().ok()?;
    synced.then_some((id, if keyed { head[64] } else { 0 }))
}
/// The flags byte of the server's latest copy the helper keeps in the sync
/// folder (`incoming`: the 16-byte wrap, then a GOYOVA04 header), else 0.
/// Only its first 81 bytes are read, for the same wording only.
fn incoming_flags(vault: &Path) -> u8 {
    let Some(dir) = syncfile::sync_dir(vault).filter(|d| syncfile::usable_dir(d)) else {
        return 0;
    };
    let mut head = [0u8; 81];
    let read = std::fs::File::open(dir.join(INCOMING)).and_then(|mut f| f.read_exact(&mut head));
    let keyed = read.is_ok() && &head[..8] == INCOMING_MAGIC && &head[16..24] == b"GOYOVA04";
    if keyed { head[80] } else { 0 }
}
/// The forced-command line of this PC's dedicated key (spec v3 §7.12,
/// docs/SYNC.md): `serve`, with `--key-sync=` and the vault IDs
/// comma-separated when there are any. None when the script path or the
/// Python command is not one the install would run (the same checks as
/// `setup::install_command`): no character of the line's options can come
/// from them.
pub fn forced_line(python: &str, remote: &str, ids: &[[u8; 16]]) -> Option<String> {
    let serve = serve_command(python, remote, ids)?;
    Some(fill(
        "restrict,command=\"{}\" <이 PC 전용 키의 공개 키> goyo-sync",
        &[&serve],
    ))
}
/// The forced command itself: `<python> -I <remote> serve`, with
/// `--key-sync=` and the vault IDs comma-separated when there are any.
/// [`forced_line`] shows it; keysetup.rs puts it on the server.
pub fn serve_command(python: &str, remote: &str, ids: &[[u8; 16]]) -> Option<String> {
    crate::setup::install_command(remote, python).ok()?;
    let mut serve = format!("{python} -I {remote} serve");
    if !ids.is_empty() {
        let named: Vec<String> = ids.iter().map(|i| syncfile::hex(i)).collect();
        serve = format!("{serve} --key-sync={}", named.join(","));
    }
    Some(serve)
}
/// A vault the forced-command line names: its ID, its file name, and
/// whether only the server's side said it uses key-file sync (the server's
/// copy or key file, not this PC's vault file or the app's request).
pub type Named = ([u8; 16], String, bool);
/// What [강제 명령 줄…] shows (spec §2.29 (sync)): the line, which names
/// the listed vaults that use key-file sync, what it does, and when to
/// take a vault out again. The vaults only the server's side names are
/// listed apart, for the user to check (spec §2.29 (sync), R18).
pub fn forced_text(python: &str, remote: &str, named: &[Named]) -> String {
    let ids: Vec<[u8; 16]> = named.iter().map(|(id, ..)| *id).collect();
    let Some(line) = forced_line(python, remote, &ids) else {
        return tr(UNSAFE_LINE).to_owned();
    };
    let note = if named.is_empty() {
        tr(
            "목록에 열쇠 파일 동기화를 쓰는 금고가 없어 --key-sync가 없는 줄입니다.\n· 새 PC라면: 먼저 '이 PC로 가져오기…'로 금고를 가져온 뒤 이 버튼을 다시 누르세요. 다른 PC에서 열쇠 파일 동기화를 켠 금고는 그때 줄에 들어갑니다.\n· 이 PC의 금고라면: 고요 금고의 '열쇠 관리 > 열쇠 파일 동기화 켜기…'에서 켠 뒤 이 버튼을 다시 누르세요.",
        )
        .to_owned()
    } else {
        let names = |server: bool| -> Vec<String> {
            named
                .iter()
                .filter(|(.., s)| *s == server)
                .map(|(id, name, _)| format!("{name} ({})", tag(id)))
                .collect()
        };
        let all: Vec<String> = named
            .iter()
            .map(|(id, name, _)| format!("{name} ({})", tag(id)))
            .collect();
        let mut note = fill(
            "열쇠 파일 동기화를 쓰는 금고를 자동으로 넣었습니다: {}. 그 금고를 쓰는 모든 PC의 줄에 같은 금고 ID가 있어야 합니다. 줄을 바꾸면 goyo-sync가 2분 안에 다시 확인합니다(바로 확인하려면 '저장하고 시작'). 열쇠 파일 동기화를 끄고 모든 PC가 받았으면 그 ID를 줄에서 빼세요: 줄에 남은 금고는 이 PC의 동기화 키를 훔친 사람이 업로드를 막을 수 있습니다.",
            &[&all.join(", ")],
        );
        let server = names(true);
        if !server.is_empty() {
            note = format!(
                "{note}\n{}",
                fill(
                    "그중 {}은(는) 서버 쪽 정보(서버 사본이나 서버의 열쇠 파일)만 보고 넣었습니다. 이 PC나 다른 PC에서 직접 열쇠 파일 동기화를 켠 금고가 맞는지 확인하고, 아니면 그 ID를 줄에서 빼세요.",
                    &[&server.join(", ")],
                )
            );
        }
        note
    };
    let manual = fill(
        "서버의 ~/.ssh/authorized_keys에서 이 PC 전용 키의 줄을 다음 한 줄로 바꾸세요. 공개 키 자리에는 그 키의 .pub 파일 내용을 넣습니다.\n\n{}\n\n이 줄은 이 PC의 전용 키로는 goyo-sync 동기화만 하게 묶습니다(셸·전달 금지). --key-sync=에 적힌 금고만 열쇠 파일을 서버와 주고받을 수 있습니다.\n{}\n\n이 창에서 Ctrl+C를 누르면 창의 글 전체가 복사되니, authorized_keys에는 restrict,command=로 시작하는 그 한 줄만 남기세요.",
        &[&line, &note],
    );
    format!(
        "{}

{manual}",
        tr(AUTO_LINE)
    )
}

/// [서버에 설치·업데이트]'s one question (keysetup.rs): what is installed,
/// which key, the line that goes into authorized_keys (the public key
/// named, not shown: a new key does not exist yet), what `--key-sync`
/// allows and what it does not, and that the usual login does it.
pub fn setup_question(c: &Config, plan: &Plan) -> String {
    let path = plan.key.path().display();
    let key = match plan.key {
        Key::New(_) => fill(
            "새로 만듭니다 · {} (ed25519, 암호 없음: 백그라운드 도우미가 혼자 씁니다. 이 Windows 계정만 읽을 수 있게 합니다)",
            &[&path],
        ),
        Key::Existing(_) => fill("있는 키를 씁니다 · {}", &[&path]),
    };
    let name = plan
        .key
        .path()
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let line = match serve_command(&c.python, &c.remote, &plan.ids) {
        Some(serve) => format!(
            "restrict,command=\"{serve}\" ssh-ed25519 {} {}",
            fill("<{}의 공개 키>", &[&name]),
            plan.comment
        ),
        None => tr(UNSAFE_LINE).to_owned(),
    };
    let mut ids = if plan.ids.is_empty() {
        tr("목록에 ID를 아는 금고가 없어 --key-sync가 없는 줄입니다(동기화만, 열쇠 파일 동기화는 안 됨). 금고를 넣은 뒤 이 버튼을 다시 누르면 줄이 바뀝니다.").to_owned()
    } else {
        fill(
            "--key-sync=에는 이 창 목록의 금고 {}개의 ID가 모두 들어가, 그 금고들은 열쇠 파일을 이 서버에 둘 수 있게 됩니다. 그래도 고요 금고의 '열쇠 관리'에서 열쇠 파일 동기화를 켜기 전에는 서버에 열쇠 파일이 생기지 않습니다(금고 앱이 보내지 않은 열쇠 파일을 서버가 만들 일은 없음).",
            &[&plan.ids.len()],
        )
    };
    if plan.unknown > 0 {
        ids = format!(
            "{ids} {}",
            fill(
                "ID를 아직 모르는 금고 {}개(파일이 아직 없거나 동기화 형식이 아님)는 빠졌습니다. 동기화가 시작된 뒤 이 버튼을 다시 누르세요.",
                &[&plan.unknown],
            )
        );
    }
    fill(
        "{} 서버에 동기화 스크립트를 설치하거나 업데이트하고, 이 PC의 동기화 전용 키를 서버에 등록합니다.

1. 스크립트: {}에 보내 {} -I로 selftest하고, PASS일 때만 기존 스크립트와 바꿉니다.
2. 전용 키: {}
3. 서버의 ~/.ssh/authorized_keys에 이 PC의 줄을 넣습니다. 같은 키의 줄이 있으면 그 줄만 바꾸고 다른 줄은 그대로 둡니다. 바꾸기 전에 authorized_keys.goyo-backup으로 백업합니다.

{}

{}
4. 전용 키로 연결을 확인한 뒤 goyo-sync.conf의 전용 SSH 키 파일로 저장합니다.

설치와 등록에는 평소의 ssh 로그인(기본 키나 ssh-agent)을 쓰고, 전용 키는 쓰지 않습니다. 계속할까요?",
        &[&c.host, &c.remote, &c.python, &key, &line, &ids],
    )
}
/// The server line after the setup succeeded: how many vaults the line
/// names, and whether goyo-sync.conf still waits for '저장하고 시작'.
pub fn ready_text(vaults: usize, saved: bool) -> String {
    let done = fill(
        "서버 설치 완료 · 동기화 전용 키 설정됨 (열쇠 파일 동기화 가능: 금고 {}개)",
        &[&vaults],
    );
    if saved {
        done
    } else {
        format!("{done} · {}", tr("'저장하고 시작'을 누르면 적용됩니다"))
    }
}
/// The server line when the setup stopped after the install (the cases
/// gui.rs does not word itself: ssh failures, an unsafe setting, a
/// cancel).
pub fn stop_text(outcome: &Outcome) -> String {
    let clear = tr("'전용 SSH 키 파일'을 비우고 다시 누르면 새 키를 만듭니다.");
    match outcome {
        Outcome::NoHome => tr("스크립트는 설치했지만 전용 키를 둘 폴더(%USERPROFILE%\\.ssh)를 찾지 못했습니다. 서버는 그대로입니다.").to_owned(),
        Outcome::Taken => tr("스크립트는 설치했지만 새 키 이름의 파일이 그새 생겨 덮어쓰지 않았습니다. 다시 누르세요.").to_owned(),
        Outcome::Keygen(detail) if detail.is_empty() => tr("스크립트는 설치했지만 ssh-keygen이 전용 키를 만들지 못했습니다. 서버는 그대로입니다.").to_owned(),
        Outcome::Keygen(detail) => fill(
            "스크립트는 설치했지만 ssh-keygen이 전용 키를 만들지 못했습니다({}). 서버는 그대로입니다.",
            &[&cut(detail)],
        ),
        Outcome::Acl => tr("스크립트는 설치했지만 새 전용 키를 이 Windows 계정만 읽게 하지 못했습니다(icacls). 서버는 그대로입니다.").to_owned(),
        Outcome::Unreadable { permissions: true } => tr("스크립트는 설치했지만 다른 계정도 전용 키 파일을 읽을 수 있어 ssh-keygen이 읽지 않았습니다. 안내대로 고친 뒤 다시 누르세요.").to_owned(),
        Outcome::Unreadable { permissions: false } => format!(
            "{} {clear}",
            tr("스크립트는 설치했지만 전용 키 파일을 읽지 못했습니다(암호가 걸린 키는 쓸 수 없음).")
        ),
        Outcome::NotEd25519 => format!(
            "{} {clear}",
            tr("스크립트는 설치했지만 전용 키가 ed25519가 아니어서 등록하지 않았습니다.")
        ),
        Outcome::Unrestricted => format!(
            "{} {clear}",
            tr("스크립트는 설치했지만 서버에 이 키가 강제 명령 없이(평소 로그인 키로) 있어 authorized_keys를 바꾸지 않았습니다.")
        ),
        Outcome::Script(line) => fill(
            "스크립트는 설치했지만 서버의 authorized_keys를 고치지 못했습니다. 서버 출력: {}",
            &[&cut(line)],
        ),
        Outcome::Verify(_) => tr("서버에 이 PC의 줄은 넣었지만 전용 키로 접속하지 못해 goyo-sync.conf는 그대로 두었습니다. '로그 보기'에서 이유를 확인하세요.").to_owned(),
        Outcome::Ready(_) | Outcome::Refused(_) | Outcome::Failed(_) | Outcome::Cancelled => {
            String::new()
        }
    }
}
/// At most 80 characters of a program's output in a line.
fn cut(text: &str) -> String {
    let mut s: String = text.chars().take(80).collect();
    if text.chars().count() > 80 {
        s.push('…');
    }
    s
}

/// What a listed vault's key view says the server holds as its key file,
/// as the helper last saw it with this PC's line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Here {
    /// No key view (the helper has not asked, or no sync folder).
    #[default]
    Unknown,
    Held,
    Missing,
    /// `line` 1: this PC's line has no `--key-sync` for the vault.
    NotAllowed,
}
/// A vault row's key-file look (spec §2.29 (sync)): from the sync folder's
/// listing, and, when the stamps of `kreq` or `kview` changed, the key view
/// and the vault ID the helper pinned. Never the vault or a key file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyLook {
    stamps: Option<(Option<Stamp>, Option<Stamp>)>,
    pub here: Here,
    /// The app wrote a key request (`kreq`): this vault uses key-file sync.
    pub requested: bool,
    /// The vault ID the helper pinned for the folder.
    pub id: Option<[u8; 16]>,
}
impl KeyLook {
    /// Reads again when the listing changed; true if anything shown did.
    pub fn refresh(&mut self, vault: &Path) -> bool {
        let Some(dir) = syncfile::sync_dir(vault).filter(|d| syncfile::usable_dir(d)) else {
            let changed = *self != Self::default();
            *self = Self::default();
            return changed;
        };
        let stamps = (
            syncfile::stamp(&dir, KEY_REQUEST),
            syncfile::stamp(&dir, KEY_VIEW),
        );
        if self.stamps == Some(stamps) {
            return false;
        }
        let id = syncfile::read_helper_state(&dir).and_then(|s| s.id);
        let read = id.map(|_| syncfile::read_bounded(&dir.join(KEY_VIEW), MAX_KEY_VIEW));
        // Held open by the helper or the app: the next tick reads it.
        let busy = matches!(read, Some(Err(FileError::Busy)));
        let view = id
            .zip(read.and_then(Result::ok))
            .and_then(|(id, bytes)| parse_key_view(&bytes, &id));
        let here = match view {
            None => Here::Unknown,
            Some(v) if v.line == 1 => Here::NotAllowed,
            Some(v) => match parse_record_header(&v.record) {
                Some((RecordKind::Key, false, ..)) if v.seq > 0 => Here::Held,
                _ => Here::Missing,
            },
        };
        let next = Self {
            stamps: (!busy).then_some(stamps),
            here,
            requested: stamps.0.is_some(),
            id,
        };
        let changed = (next.here, next.requested, next.id) != (self.here, self.requested, self.id);
        *self = next;
        changed
    }
}
/// A row's state with what the server holds as its key file: "… · 열쇠:
/// 서버에 있음 / 서버에 없음 / 서버가 허용 안 함". The `nokeys` state says
/// it already. A line without `--key-sync` is said only for a vault that
/// uses key-file sync (`uses`): for any other vault, a key file kept on
/// this PC, it is no problem and says nothing.
pub fn with_key(state: String, look: &KeyLook, uses: bool) -> String {
    if state == no_keys() {
        return state;
    }
    let key = match look.here {
        Here::Unknown => return state,
        Here::NotAllowed if !uses => return state,
        Here::Held => tr("열쇠: 서버에 있음"),
        Here::Missing => tr("열쇠: 서버에 없음"),
        Here::NotAllowed => tr("열쇠: 서버가 허용 안 함"),
    };
    format!("{state} · {key}")
}
/// The vault ID to name in `--key-sync` when the listed vault uses
/// key-file sync, and whether only the server's side says so (`true`).
/// This PC's side: the vault file's header says GOYOKS01 (flags bit1) or
/// the app wrote a key request. The server's side: its latest copy says
/// so (another PC turned it on), it holds the vault's key file, or the
/// helper shows `nokeys` for it.
pub fn uses_key_sync(vault: &Path, look: &KeyLook, live: Live) -> Option<([u8; 16], bool)> {
    let header = vault_header(vault);
    let id = header.map(|(id, _)| id).or(look.id)?;
    let here = header.is_some_and(|(_, flags)| flags & 2 != 0) || look.requested;
    let server = incoming_flags(vault) & 2 != 0
        || look.here == Here::Held
        || matches!(
            live,
            Live::State {
                state: SyncState::NoKeys,
                ..
            }
        );
    (here || server).then_some((id, !here))
}

/// The list label of `nokeys` (spec v3 §7.12, §2.29 (sync)): this PC's
/// server line has no `--key-sync=<id>` for a vault that uses key-file
/// sync. The helper asks again every two minutes.
pub fn no_keys() -> &'static str {
    tr("열쇠: 서버가 허용 안 함 · '서버에 설치·업데이트'를 다시 누르세요")
}
/// A server-list row's key file (the list of "이 PC로 가져오기").
pub fn server_key(key: ServerKey) -> Option<&'static str> {
    Some(tr(match key {
        ServerKey::Held => "열쇠 파일: 서버에 있음",
        ServerKey::Missing => "열쇠 파일: 서버에 없음 (USB로)",
        ServerKey::NotAllowed => "열쇠 파일: 이 PC 줄로는 확인 안 함",
        ServerKey::Unknown => return None,
    }))
}
/// What "이 PC로 가져오기" says once the vault file was saved, by what
/// GETKEY did (S6-3 #20, spec §2.29 (sync)): the server's key file came
/// along, and the vault app continues with its code; or the key file comes
/// by USB (`usb`, gui.rs's text, given the reason here).
pub fn fetched(
    version: u64,
    bytes: usize,
    path: &Path,
    key: &KeyGot,
    steps: [&str; 2],
    usb: &dyn Fn(&str) -> String,
) -> String {
    let [listed, open] = steps;
    let key_name = path.with_extension("goyokey");
    let key_name = key_name
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let reason = match key {
        KeyGot::Written => {
            return fill(
                "가져왔습니다: {}\n(서버 버전 {}, {}바이트, 서버의 열쇠 파일도 함께 · 아직 확인 전)\n\n다음 순서:\n1. {}\n2. {} '서버에서 가져온 금고' 화면이 이어서 안내합니다.\n3. 비밀번호와 보안 키로 연 뒤, 다른 PC의 고요 금고 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력합니다.\n4. 코드가 맞으면 열쇠 파일이 금고 옆에 {} 이름으로 저장되고, 그때부터 평소처럼 열립니다.",
                &[&path.display(), &version, &bytes, &listed, &open, &key_name],
            );
        }
        KeyGot::NoKeys => tr("이 PC의 서버 줄이 열쇠 파일 요청을 허용하지 않아 서버에 이 금고의 열쇠 파일이 있는지 알 수 없습니다. 있다면 '서버에 설치·업데이트'를 누르세요. 금고 목록에 '열쇠: 서버에 있음'이 보이면 고요 금고를 다시 열거나 '찾기'로 이 파일을 다시 고르세요. '서버에서 가져온 금고' 화면이 이어서 안내합니다. 아니면:\n").to_owned(),
        KeyGot::Empty => tr("서버에 이 금고의 열쇠 파일이 없습니다(이 금고는 열쇠 파일을 PC에만 둡니다).\n").to_owned(),
        KeyGot::BadAnswer | KeyGot::WriteFailed | KeyGot::Failed(_) => {
            let why = match key {
                KeyGot::BadAnswer => tr("서버 응답 형식").to_owned(),
                KeyGot::WriteFailed => tr("파일 쓰기").to_owned(),
                KeyGot::Failed(detail) if !detail.is_empty() => detail.clone(),
                _ => tr("연결").to_owned(),
            };
            fill("서버의 열쇠 파일은 받지 못했습니다({}).\n", &[&why])
        }
    };
    usb(&reason)
}
