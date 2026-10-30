//! The security-key build's words in goyo-sync's window (spec v3 §9.3): a
//! file only that build compiles, so the default exe carries none of them,
//! with their English in `i18n::EN_SK`.
use crate::{
    i18n::{fill, tr},
    setup::KeyGot,
    syncfile,
};
use std::{io::Read, path::Path};

/// The toggle of the settings window's vault list (spec v3 §7.12): the
/// selected vault is named in the forced-command line's `--key-sync`.
/// Shown only, never stored in goyo-sync.conf.
pub const ALLOW: &str = "열쇠 파일 동기화 허용 (실험)";
/// The button that shows the forced-command line.
pub const LINE_BUTTON: &str = "강제 명령 줄…";
/// The selected file is not a synced vault, so it has no vault ID to name.
pub const NO_ID: &str = "이 파일에서 금고 ID를 읽을 수 없습니다. 동기화를 켠 고요 금고 파일만 열쇠 파일 동기화에 넣을 수 있습니다.";
/// The vaults `--key-sync` can name at most (spec v3 §7.13). The line
/// names only vaults in the settings list, which holds fewer, so none is
/// ever left out.
const MAX_IDS: usize = 64;
const _: () = assert!(crate::config::MAX_VAULTS <= MAX_IDS);
/// The script path or the Python command could close the line's quoted
/// command (a `"`, a `,`, a line break): no line is shown, as no install
/// command is run with them.
pub const UNSAFE_LINE: &str = "고급 설정의 스크립트 경로나 파이썬 명령에 쓸 수 없는 글자가 있어 강제 명령 줄을 만들지 않았습니다. 그 두 칸을 고친 뒤 다시 누르세요.";

/// The vault ID of a synced vault file (GOYOVA02 or GOYOVA04): bytes
/// 8..24 of its header. None for any other file.
pub fn vault_id(path: &Path) -> Option<[u8; 16]> {
    let mut head = [0u8; 24];
    std::fs::File::open(path).ok()?.read_exact(&mut head).ok()?;
    let synced = head.starts_with(b"GOYOVA02") || head.starts_with(b"GOYOVA04");
    synced.then(|| head[8..24].try_into().ok()).flatten()
}
/// The forced-command line of this PC's dedicated key (spec v3 §7.12,
/// docs/SYNC.md): `serve`, with `--key-sync=` and the vault IDs
/// comma-separated when there are any. None when the script path or the
/// Python command is not one the install would run (the same checks as
/// `setup::install_command`): no character of the line's options can come
/// from them.
pub fn forced_line(python: &str, remote: &str, ids: &[[u8; 16]]) -> Option<String> {
    crate::setup::install_command(remote, python).ok()?;
    let mut serve = format!("{python} -I {remote} serve");
    if !ids.is_empty() {
        let named: Vec<String> = ids.iter().map(|i| syncfile::hex(i)).collect();
        serve = format!("{serve} --key-sync={}", named.join(","));
    }
    Some(fill(
        "restrict,command=\"{}\" <이 PC 전용 키의 공개 키> goyo-sync",
        &[&serve],
    ))
}
/// What [강제 명령 줄…] shows: the line, and when and for which vaults to
/// name a vault in it (spec v3 §7.12, S6-3 #3).
pub fn forced_text(python: &str, remote: &str, ids: &[[u8; 16]]) -> String {
    let Some(line) = forced_line(python, remote, ids) else {
        return tr(UNSAFE_LINE).to_owned();
    };
    let note = if ids.is_empty() {
        tr(
            "열쇠 파일 동기화를 허용한 금고가 없어 --key-sync 없는 줄입니다. 열쇠 파일 동기화를 쓸 금고를 목록에서 고르고 '열쇠 파일 동기화 허용 (실험)'을 켜세요.",
        )
    } else {
        tr(
            "열쇠 파일 동기화를 쓰는 금고만 넣으세요. 금고 ID는 그 금고에서 열쇠 파일 동기화를 켜기 직전에 그 금고를 쓰는 모든 PC의 줄에 넣고, 끈 뒤 모든 PC가 받았으면 모든 PC의 줄에서 빼세요. 줄에 이름이 있는 금고는 꺼져 있어도 서버에 열쇠 기록이 남아, 그 줄의 동기화 키를 훔친 사람이 업로드를 막을 수 있습니다.",
        )
    };
    fill(
        "서버의 ~/.ssh/authorized_keys에서 이 PC 전용 키의 줄을 다음처럼 쓰세요. 공개 키 자리에는 그 키의 .pub 파일 내용을 넣습니다. 이 창에서 Ctrl+C를 누르면 창의 글 전체가 복사되니, authorized_keys에는 restrict,command=로 시작하는 그 한 줄만 남기세요.\n\n{}\n\n{}",
        &[&line, &note],
    )
}

/// The list label of `nokeys` (spec v3 §7.12): this PC's server line has
/// no `--key-sync=<id>` for a vault that uses key-file sync.
pub fn no_keys() -> &'static str {
    tr("서버에서 열쇠 파일 동기화 꺼짐")
}
/// "열쇠 파일도 받기" on the server list (spec v3 §7.12, §7.17), on or off.
pub fn fetch_key_label(on: bool) -> &'static str {
    tr(if on {
        "열쇠 파일도 받기: 켬"
    } else {
        "열쇠 파일도 받기: 끔"
    })
}
/// What the fetch says after the vault version, by what GETKEY did
/// (S6-3 #20): the way to open both from the server, or S-FETCHKEY-*.
pub fn fetched(version: u64, bytes: usize, path: &Path, key: &KeyGot) -> String {
    match key {
        KeyGot::Written => fill(
            "서버 버전 {}({}바이트)을 다음 파일로 받았습니다:\n{}\n\n서버의 열쇠 파일도 그 옆 동기화 폴더에 받았습니다(아직 확인 전).\n이렇게 여세요.\n1. 고요 금고(보안 키 빌드)에서 '백업에서 복원'을 누르고 이 파일을 고릅니다.\n2. '서버에서 받은 열쇠 파일 (확인 전) 쓰기'를 누르고, '복원할 새 파일'을 이 PC에서 동기화할 경로로 정한 뒤 비밀번호와 보안 키로 엽니다.\n3. 다른 PC의 '열쇠 관리'에 지금 보이는 열쇠 확인 코드를 입력하고, 열쇠 파일을 저장할 곳(동기화 폴더 밖)을 고릅니다.\n4. 복원한 금고 파일을 여기서 '추가…'로 넣고 '저장하고 시작'을 누릅니다.",
            &[&version, &bytes, &path.display()],
        ),
        KeyGot::NoKeys => tr("금고 파일은 저장했습니다. 이 PC의 서버 연결은 이 금고의 열쇠 파일 요청을 받지 않습니다(서버 강제 명령에 --key-sync=<금고 ID> 없음). 열쇠 파일은 다른 PC에서 USB로 복사하세요.").to_owned(),
        KeyGot::Empty => tr("금고 파일은 저장했습니다. 서버에 이 금고의 열쇠 파일이 없습니다(열쇠 파일 동기화를 쓰지 않거나 껐음). 열쇠 파일은 다른 PC에서 USB로 복사하세요.").to_owned(),
        KeyGot::BadAnswer | KeyGot::WriteFailed | KeyGot::Failed(_) => {
            let reason = match key {
                KeyGot::BadAnswer => tr("서버 응답 형식").to_owned(),
                KeyGot::WriteFailed => tr("파일 쓰기").to_owned(),
                KeyGot::Failed(detail) => detail.clone(),
                _ => String::new(),
            };
            fill(
                "금고 파일은 저장했습니다. 열쇠 파일은 받지 못했습니다({reason}). 열쇠 파일은 다른 PC에서 USB로 복사하세요.",
                &[&reason],
            )
        }
    }
}
