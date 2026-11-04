//! The Korean texts of the open vault's sync news (the lib's `SyncNotice`
//! and `SyncBadge`), worded after goyo-vault.exe's status line
//! (src/main.rs `sync_line`). Where the PC app sends the user to a screen
//! this app does not have yet (the Keys screen, its gates: a key code or a
//! pick), the text says to settle it on a PC first: the lib meanwhile
//! keeps the server's key file in the sync folder and neither uploads nor
//! merges, as on a PC that has not answered its gate. No text names an
//! entry.
use goyo_vault::vault::{SyncBadge, SyncNotice};

const ON_PC: &str = "PC의 고요 금고에서 먼저 처리하세요(열쇠 관리). 그때까지 이 휴대폰은 올리지도 합치지도 않고, 변경은 이 휴대폰에 저장되어 있습니다.";

/// The badge's word: 0 synced, 1 uploading, 2 helper off, 3 offline,
/// 4 warning; -1 when the vault does not sync.
pub fn badge_code(badge: Option<SyncBadge>) -> i32 {
    match badge {
        None => -1,
        Some(SyncBadge::Synced) => 0,
        Some(SyncBadge::Uploading) => 1,
        Some(SyncBadge::HelperOff) => 2,
        Some(SyncBadge::Offline) => 3,
        Some(SyncBadge::Warning) => 4,
    }
}

/// The line for `notice` and whether it is a warning.
pub fn text(notice: &SyncNotice) -> (String, bool) {
    let plain = |s: &str| (s.to_owned(), false);
    let danger = |s: &str| (s.to_owned(), true);
    #[allow(unreachable_patterns)]
    match notice {
        SyncNotice::SyncOn => plain("동기화를 켰습니다. 서버에 올라가면 '동기화됨'이 표시됩니다."),
        SyncNotice::Merged { added, removed } => (
            format!("다른 기기의 변경을 합쳤습니다: 추가 {added}개, 삭제 {removed}개."),
            false,
        ),
        SyncNotice::Conflicts(n) => (
            format!(
                "두 기기에서 함께 고친 항목 {n}개는 두 버전을 모두 남겼습니다. 이름이 같은 항목을 확인하세요."
            ),
            false,
        ),
        SyncNotice::MassDelete { removed, file } => (
            format!(
                "다른 기기에서 항목 {removed}개가 삭제되거나 수정되었습니다. 합치기 전 상태를 {file}에 보관했습니다."
            ),
            true,
        ),
        SyncNotice::Rollback => danger(
            "경고: 서버가 이전 상태의 금고를 보냈습니다. 이 휴대폰의 항목은 그대로이며 서버에 다시 올립니다.",
        ),
        SyncNotice::BadIncoming => danger(
            "서버에서 받은 금고를 인증하지 못해 무시했습니다(손상 또는 변조). 이 휴대폰의 상태를 다시 올립니다.",
        ),
        SyncNotice::ForeignIncoming => danger(
            "서버 사본이 다른 금고의 것이라 무시했습니다. 금고를 다시 가져오면 동기화 폴더가 새로 만들어집니다.",
        ),
        SyncNotice::TooLarge => {
            danger("합치면 항목 1000개 또는 8 MiB를 넘어 합치지 않았습니다. 항목을 정리하세요.")
        }
        SyncNotice::NewerFormat => {
            danger("서버 사본이 새 버전 형식이라 동기화를 멈췄습니다. 앱을 업데이트하세요.")
        }
        SyncNotice::KeyInFolder => danger("열쇠 파일이 동기화 폴더 안에 있어 동기화하지 않습니다."),
        SyncNotice::Synced { code } => (
            format!("동기화됨 · 확인 코드 {code} (다른 기기에서도 같으면 같은 내용입니다)"),
            false,
        ),
        SyncNotice::HelperOff => plain(
            "동기화가 한동안 돌지 않았습니다. 변경은 이 휴대폰에 저장되어 있고 '지금 동기화'나 다음 동기화 때 올립니다.",
        ),
        SyncNotice::Offline => {
            plain("동기화 오프라인: 변경은 이 휴대폰에 저장되어 있고 연결되면 올립니다.")
        }
        SyncNotice::HostKey => danger(
            "동기화 중단: 서버 호스트 키를 확인해야 합니다. 확인하기 전에는 연결하지 않습니다(설정 › 연결 확인).",
        ),
        SyncNotice::Auth => danger(
            "동기화 오류: 서버가 이 휴대폰의 키를 받지 않습니다. PC에서 'Android 기기 추가'로 이 휴대폰의 줄을 넣으세요.",
        ),
        SyncNotice::HelperError => {
            danger("동기화 오류: 서버 오류입니다. 변경은 이 휴대폰에 저장되어 있습니다.")
        }
        SyncNotice::OldServer => danger(
            "서버의 goyo-sync 스크립트가 이 금고 형식을 받지 않습니다. PC의 goyo-sync 설정 창에서 '서버에 설치·업데이트'를 누르세요.",
        ),
        SyncNotice::KeyBehind => (
            format!(
                "서버의 열쇠 파일 기록과 이 휴대폰의 금고 사본이 맞지 않아 서버가 업로드를 받지 않습니다(다른 기기가 열쇠를 바꿨음). {ON_PC}"
            ),
            true,
        ),
        SyncNotice::KeyChanged { .. } => (
            "다른 기기에서 이 금고의 열쇠를 바꿔 동기화를 멈췄습니다. PC에서 열쇠를 받은 뒤 두 파일(.goyo, .goyokey)을 이 휴대폰으로 다시 가져오세요. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.".to_owned(),
            true,
        ),
        SyncNotice::KeyFork => (
            format!("두 기기에서 따로 열쇠를 바꿔 열쇠 파일이 갈라졌습니다. {ON_PC}"),
            true,
        ),
        SyncNotice::OldKeyDamaged => (
            format!(
                "서버 사본이 예전 열쇠 이름을 달고 있지만 열리지 않아 동기화를 멈췄습니다(손상 또는 위조). {ON_PC}"
            ),
            true,
        ),
        SyncNotice::RollbackHeld => (
            format!(
                "이 휴대폰은 전에 쓴 것보다 오래된 열쇠 파일로 열려 있어 동기화를 멈췄습니다. 최신 열쇠 파일을 다시 가져오세요. {ON_PC}"
            ),
            true,
        ),
        SyncNotice::NewerKeyFile => (
            format!(
                "다른 기기의 열쇠 파일이 이 휴대폰의 것보다 새롭습니다. 동기화를 멈췄습니다. {ON_PC}"
            ),
            true,
        ),
        SyncNotice::OldKeyReplaced => danger(
            "예전 열쇠로 만든 서버 사본은 합치지 않고 이 휴대폰의 상태로 덮었습니다. 새 열쇠 파일을 아직 받지 않은 기기가 있으면 그 기기에서 받으세요.",
        ),
        SyncNotice::KeyRollback => {
            danger("서버가 이 휴대폰이 이미 본 것보다 오래된 열쇠 파일을 보내 받지 않았습니다.")
        }
        SyncNotice::KeyFileRefused(why) => (
            format!("서버의 열쇠 파일이 검사를 통과하지 못해 동기화를 멈췄습니다({why}). {ON_PC}"),
            true,
        ),
        SyncNotice::BadKeyIncoming => plain("서버의 열쇠 파일 기록을 읽을 수 없어 무시했습니다."),
        SyncNotice::GatePending => (
            format!(
                "다른 기기에서 바꾼 열쇠 파일이 서버에 있습니다. 확인 전에는 받지 않습니다. {ON_PC}"
            ),
            true,
        ),
        SyncNotice::KeySyncGone => (
            format!(
                "열쇠: 서버에 없음. 다른 기기에서 열쇠 파일 동기화를 껐을 수 있습니다. {ON_PC}"
            ),
            true,
        ),
        SyncNotice::KeyFileReady { epoch } => (
            format!(
                "다른 기기의 열쇠 변경(수정 {epoch})이 서버에 있습니다. 다음 잠금 해제 때 받습니다."
            ),
            false,
        ),
        SyncNotice::NoKeySync => danger(
            "열쇠: 서버가 허용 안 함. 이 휴대폰의 줄에 이 금고의 --key-sync가 없습니다. PC에서 'Android 기기 추가'를 다시 하세요.",
        ),
        SyncNotice::KeyUpRefused => (
            format!("서버가 이 휴대폰의 열쇠 파일을 받지 않았습니다. {ON_PC}"),
            true,
        ),
        SyncNotice::KeySyncHelper => plain(
            "열쇠 파일 동기화: 10분 넘게 서버를 확인하지 못했습니다. '지금 동기화'를 누르세요.",
        ),
        SyncNotice::KeySyncDeleted { seq, .. } => (
            format!("서버가 열쇠 파일 삭제를 받았다고 응답했습니다 (기록 {seq})."),
            false,
        ),
        SyncNotice::KeyChangedServer | SyncNotice::KeyChangedServerPwOnly => (
            format!("다른 기기에서 이 금고의 열쇠를 바꿔 동기화를 멈췄습니다. {ON_PC}"),
            true,
        ),
        SyncNotice::KeyForkMerge { .. } => (
            format!("두 기기에서 따로 한 보안 키 제거를 합쳐야 합니다. {ON_PC}"),
            true,
        ),
        _ => (String::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_notice_has_a_line() {
        let all = [
            SyncNotice::SyncOn,
            SyncNotice::Merged {
                added: 1,
                removed: 2,
            },
            SyncNotice::Conflicts(3),
            SyncNotice::Rollback,
            SyncNotice::BadIncoming,
            SyncNotice::ForeignIncoming,
            SyncNotice::TooLarge,
            SyncNotice::NewerFormat,
            SyncNotice::KeyInFolder,
            SyncNotice::Synced {
                code: "AAAA-BBBB-CCCC-DDDD".into(),
            },
            SyncNotice::HelperOff,
            SyncNotice::Offline,
            SyncNotice::HostKey,
            SyncNotice::Auth,
            SyncNotice::HelperError,
            SyncNotice::OldServer,
            SyncNotice::KeyBehind,
            SyncNotice::KeyChanged { hardware: true },
            SyncNotice::KeyFork,
            SyncNotice::OldKeyDamaged,
            SyncNotice::RollbackHeld,
            SyncNotice::NewerKeyFile,
            SyncNotice::OldKeyReplaced,
            SyncNotice::KeyRollback,
            SyncNotice::KeyFileRefused("x"),
            SyncNotice::BadKeyIncoming,
            SyncNotice::GatePending,
            SyncNotice::KeySyncGone,
            SyncNotice::KeyFileReady { epoch: 4 },
            SyncNotice::NoKeySync,
            SyncNotice::KeyUpRefused,
            SyncNotice::KeySyncHelper,
            SyncNotice::KeySyncDeleted {
                seq: 2,
                admin: false,
            },
            SyncNotice::KeyChangedServer,
            SyncNotice::KeyChangedServerPwOnly,
            SyncNotice::KeyForkMerge { auto: false },
        ];
        for n in &all {
            assert!(!text(n).0.is_empty(), "{n:?}");
        }
        assert!(
            text(&SyncNotice::GatePending)
                .0
                .contains("PC의 고요 금고에서 먼저 처리하세요")
        );
    }
}
