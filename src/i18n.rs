//! Interface language. The code keeps its Korean text; whatever is shown
//! passes through tr(), which returns the English text while English is on.
//! A test checks that every Korean literal in the source has an entry here.
use std::{
    collections::BTreeMap,
    fmt::Display,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

static ENGLISH: AtomicBool = AtomicBool::new(false);

pub fn english() -> bool {
    ENGLISH.load(Ordering::Relaxed)
}
pub fn set_english(on: bool) {
    ENGLISH.store(on, Ordering::Relaxed);
}
/// The text to show for `ko`: itself in Korean, its translation in English.
/// Text without an entry (paths, entry names) is shown as it is. A BTreeMap,
/// not a HashMap: hashing would import the Windows random number generator.
pub fn tr(ko: &str) -> &str {
    if !english() {
        return ko;
    }
    static TABLE: OnceLock<BTreeMap<&'static str, &'static str>> = OnceLock::new();
    TABLE
        .get_or_init(|| {
            let table = EN.iter().copied();
            #[cfg(feature = "security-key")]
            let table = table.chain(EN_SK.iter().copied());
            table.collect()
        })
        .get(ko)
        .copied()
        .unwrap_or(ko)
}
/// tr() for a template, with each `{…}` replaced by the next argument.
pub fn fill(ko: &str, args: &[&dyn Display]) -> String {
    let mut rest = tr(ko);
    let mut args = args.iter();
    let mut out = String::new();
    while let (Some(start), Some(end)) = (rest.find('{'), rest.find('}')) {
        out.push_str(&rest[..start]);
        if let Some(arg) = args.next() {
            out.push_str(&arg.to_string());
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}
/// Korean text shown as it is in both languages.
#[cfg(test)]
pub const KEEP: &[&str] = &["맑은 고딕", "고요 금고 · Goyo Vault", "한국어"];
pub const EN: &[(&str, &str)] = &[
    (
        "'되살린 금고를 저장할 새 위치'에 같은 이름의 파일이 이미 있습니다. 다른 이름을 지정하세요.",
        "A file with that name already exists at 'New location for the restored vault'. Choose another name.",
    ),
    ("+ 새 항목", "+ New entry"),
    ("12자 이상의\n긴 문장", "12+ characters,\na long phrase"),
    ("15초 보기", "Show 15 s"),
    ("1분", "1m"),
    (
        "2분 동안 쓰지 않아 OTP 화면을 닫았습니다.",
        "Closed the OTP screen after 2 minutes without use.",
    ),
    ("30분", "30m"),
    ("5분", "5m"),
    ("API 키", "API key"),
    (
        "CON·NUL·COM1 같은 장치 이름은 파일 이름으로 쓸 수 없습니다.",
        "Device names such as CON, NUL or COM1 cannot be used as file names.",
    ),
    (
        "CPU 난수 검사가 실패했습니다. 작업을 중단했습니다.",
        "The CPU random number check failed. The operation was stopped.",
    ),
    (
        "CPU 난수 공급을 사용할 수 없습니다. 잠시 후 다시 시도하세요.",
        "The CPU random number source is unavailable. Try again in a moment.",
    ),
    (
        "DLL 검색 경로 보호 설정에 실패했습니다.",
        "Could not protect the DLL search path.",
    ),
    (
        "Google Authenticator → + → QR 코드 스캔\r\nOTP 앱 안의 스캐너로만 찍고, 사진으로 남기지 마세요.",
        "Google Authenticator → + → Scan a QR code\r\nScan only inside the OTP app; never take a photo.",
    ),
    ("Google OTP 6자리", "6-digit OTP code"),
    ("KDF 설정 오류", "Key derivation settings error"),
    (
        "NUL 문자는 저장할 수 없습니다.",
        "NUL characters cannot be stored.",
    ),
    ("OTP 6자리 · {tag}", "OTP code · {tag}"),
    ("OTP 끄기", "OTP off"),
    (
        "OTP 등록 정보는 두 번째 잠금 수단이라 금고가 열려 있어도 비밀번호를 다시 확인합니다.",
        "The OTP setup is a second lock, so the password is asked again even with the vault open.",
    ),
    ("OTP 백업", "OTP backup"),
    ("OTP 없이 금고 만들기", "Create vault without OTP"),
    (
        "OTP 없이 비밀번호와 열쇠 파일로만 여는 금고를 만듭니다. 이 PC를 다른 사람도 쓸 수 있다면 OTP를 켜 두세요.",
        "This vault will open with the password and key file only. If others can use this PC, turn on the OTP.",
    ),
    ("OTP 켜기", "Turn on OTP"),
    (
        "OTP가 틀렸거나 이미 사용되었습니다. 휴대폰·PC 시간을 확인하고 새 번호를 입력하세요.",
        "The OTP code is wrong or already used. Check the phone and PC clocks and enter a new code.",
    ),
    ("OTP는 숫자 6자리입니다.", "The OTP code is 6 digits."),
    ("QR 보기", "Show QR"),
    (
        "RDSEED를 지원하는 x64 CPU가 필요합니다. 약한 난수로 대체하지 않습니다.",
        "An x64 CPU with RDSEED is required. The app never falls back to weaker randomness.",
    ),
    (
        "Windows 11 이상에서 실행하세요.",
        "Run this on Windows 11 or later.",
    ),
    (
        "Windows 세션이 잠기거나 연결이 변경되어 잠갔습니다.",
        "Locked: the Windows session was locked or its connection changed.",
    ),
    ("Windows 종료로 잠갔습니다.", "Locked for Windows shutdown."),
    ("Windows에서만 지원합니다.", "Only Windows is supported."),
    ("x64 CPU만 지원합니다.", "Only x64 CPUs are supported."),
    ("{} / {} 페이지", "Page {} / {}"),
    ("{}초 뒤 다시 가려집니다.", "Hidden again in {} s."),
    ("‹ 뒤로", "‹ Back"),
    (
        "가려짐 · 보기를 누르면 비밀정보와 함께 표시됩니다.",
        "Hidden · shown with the secret when you press Show.",
    ),
    ("가리기", "Hide"),
    (
        "같은 글자를 반복한 비밀번호는 쓸 수 없습니다. 서로 다른 글자가 6개 이상 필요합니다.",
        "A password of repeated characters is not allowed. Use at least 6 different characters.",
    ),
    (
        "같은 이름의 파일이 이미 있습니다. 새 금고·열쇠 파일 이름을 바꾸세요.",
        "A file with that name already exists. Rename the new vault or key file.",
    ),
    (
        "경고: 서버가 이전 상태의 금고를 보냈습니다. 이 PC의 항목은 그대로이며 서버에 다시 올립니다.",
        "Warning: the server sent an older state of the vault. Nothing here changed; this PC uploads its data again.",
    ),
    ("경로 오류", "Path error"),
    ("경로 확인 실패", "Could not check the path"),
    ("고요 금고", "Goyo Vault"),
    (
        "고요 금고/백업 (*.goyo)\0*.goyo\0모든 파일\0*.*\0",
        "Goyo vault or backup (*.goyo)\0*.goyo\0All files\0*.*\0",
    ),
    (
        "고요 열쇠 파일 (*.goyokey)\0*.goyokey\0모든 파일\0*.*\0",
        "Goyo key file (*.goyokey)\0*.goyokey\0All files\0*.*\0",
    ),
    ("권장", "Recommended"),
    ("금고 백업", "Back up vault"),
    (
        "금고 백업을 저장했습니다. 열 때 열쇠 파일, 비밀번호, OTP도 필요합니다.",
        "Vault backup saved. Opening it also needs the key file, the password and the OTP.",
    ),
    (
        "금고 백업을 저장했습니다. 열 때 열쇠 파일과 비밀번호도 필요합니다.",
        "Vault backup saved. Opening it also needs the key file and the password.",
    ),
    ("금고 열기", "Open vault"),
    (
        "금고 용량 제한(8 MiB)을 초과했습니다.",
        "The vault size limit (8 MiB) was exceeded.",
    ),
    ("금고 파일", "Vault file"),
    (
        "금고 파일을 아직 새 열쇠로 다시 저장하지 못했습니다. 저장장치를 확인하세요. 다음 저장이나 잠금 해제 때 자동으로 마칩니다.",
        "The vault file could not be saved again under the new key yet. Check the storage device. It finishes on its own at the next save or unlock.",
    ),
    (
        "금고 파일을 새 열쇠로 다시 저장하지 못했습니다. 새 형식은 머리글이 44바이트 더 길어 용량 제한(8 MiB)을 넘습니다. 항목을 지우거나 줄이면 그 저장 때 마칩니다.",
        "The vault file could not be saved again under the new key: the new format's header is 44 bytes longer and would exceed the size limit (8 MiB). Delete or shorten entries, and that save finishes it.",
    ),
    (
        "금고 파일을 찾을 수 없습니다. 경로를 확인하거나 '찾기'로 선택하세요.",
        "Vault file not found. Check the path or choose it with 'Browse'.",
    ),
    (
        "금고 파일의 머리글이 손상되어 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다. 백업에서 복원하거나 서버 기록을 확인하세요.",
        "The vault file's header is damaged, so it cannot be opened. Your password is not wrong. Restore from a backup or check the server history.",
    ),
    (
        "금고 파일이 없어, 저장이 끊기며 남은 임시 파일에서 복구했습니다.",
        "The vault file was missing; it was recovered from the temporary file an interrupted save left.",
    ),
    (
        "금고·열쇠 파일을 확인하고 비밀번호를 입력하세요.",
        "Check the vault and key files and enter your password.",
    ),
    ("금고가 잠겼습니다.", "The vault is locked."),
    ("금고를 열 때 필요한 것", "What opens a vault"),
    (
        "금고와 따로 보관\n(.goyokey)",
        "Kept apart from\nthe vault (.goyokey)",
    ),
    (
        "금고와 열쇠, 백업 대상은 서로 다른 파일이어야 합니다.",
        "The vault, the key and the backup must be different files.",
    ),
    (
        "기존 파일을 덮어쓰지 않습니다. 새 파일 이름을 선택하세요.",
        "Existing files are never overwritten. Choose a new file name.",
    ),
    ("니모닉", "Seed phrase"),
    (
        "다른 PC에서 항목 {}개가 삭제되거나 수정되었습니다. 합치기 전 상태를 {}에 보관했습니다.",
        "{} entries were deleted or edited on another PC. The state before merging was kept in {}.",
    ),
    (
        "다른 PC의 변경을 합쳤습니다: 추가 {}개, 삭제 {}개.",
        "Merged changes from another PC: {} added, {} removed.",
    ),
    (
        "다른 고요 금고에서 사용 중인 파일입니다.",
        "This file is in use by another Goyo Vault window.",
    ),
    (
        "다른 앱에 30초 넘게 머물러 잠갔습니다.",
        "Locked after more than 30 s in another app.",
    ),
    (
        "다른 앱으로 전환되어 OTP 화면을 닫았습니다.",
        "The OTP screen closed because you switched apps.",
    ),
    (
        "금고 파일 열기 (다른 폴더 · 서버에서 가져온 금고)",
        "Open a vault file (other folder or brought from the server)",
    ),
    (
        "다른 프로그램의 메모리 접근 차단 설정에 실패했습니다.",
        "Could not block other programs from this app's memory.",
    ),
    (
        "다른 프로그램의 메모리 접근 차단을 확인하지 못했습니다.",
        "Could not confirm that other programs are blocked from this app's memory.",
    ),
    (
        "다른 프로그램이 클립보드를 사용 중입니다.",
        "Another program is using the clipboard.",
    ),
    ("다크", "Dark"),
    ("닫기", "Close"),
    (
        "대화상자가 열린 동안 잠겼습니다. 다시 인증하세요.",
        "The vault locked while the dialog was open. Unlock it again.",
    ),
    (
        "더 새로운 버전에서 만든 금고 형식입니다. 고요 금고를 업데이트하세요.",
        "This vault was saved by a newer version. Update Goyo Vault.",
    ),
    (
        "더 새로운 버전에서 만든 열쇠 파일입니다. 고요 금고를 업데이트하세요.",
        "This key file was made by a newer version. Update Goyo Vault.",
    ),
    ("도우미 꺼짐", "Helper off"),
    ("동기화 경고", "Sync warning"),
    (
        "동기화 도우미(goyo-sync.exe)가 실행 중이 아닙니다. 변경은 이 PC에 저장되어 있습니다.",
        "The sync helper (goyo-sync.exe) is not running. Your changes are saved on this PC.",
    ),
    (
        "동기화 오류: SSH 인증에 실패했습니다. goyo-sync.log를 확인하세요.",
        "Sync error: SSH authentication failed. See goyo-sync.log.",
    ),
    (
        "동기화 오류: goyo-sync.log를 확인하세요. 변경은 이 PC에 저장되어 있습니다.",
        "Sync error: see goyo-sync.log. Your changes are saved on this PC.",
    ),
    (
        "동기화 오프라인: 변경은 이 PC에 저장되어 있고 연결되면 올립니다.",
        "Sync offline: changes are saved on this PC and upload once connected.",
    ),
    (
        "동기화 중단: 서버 호스트 키가 바뀌었습니다. 확인하기 전에는 연결하지 않습니다.",
        "Sync stopped: the server's host key changed. goyo-sync will not connect until you check it.",
    ),
    ("동기화됨", "Synced"),
    (
        "동기화됨 · 확인 코드 {} (다른 PC에서도 같으면 같은 내용입니다)",
        "Synced · check code {} (the same code on another PC means the same contents)",
    ),
    (
        "동기화를 켰습니다. 서버에 올라가면 위에 '동기화됨'이 표시됩니다.",
        "Sync is on. 'Synced' appears at the top once the vault is on the server.",
    ),
    (
        "두 PC에서 함께 고친 항목 {}개는 두 버전을 모두 남겼습니다. 이름이 같은 항목을 확인하세요.",
        "Entries edited on two PCs: {}. Both versions were kept; check entries with the same name.",
    ),
    (
        "등록 키를 종이에 적어 두어도 됩니다. 사진으로는 남기지 마세요.\r\n다른 앱으로 전환하면 이 QR은 바로 닫힙니다.",
        "You may write the setup key on paper, but never take a photo.\r\nSwitching to another app closes this QR at once.",
    ),
    ("등록 확인 · 금고 만들기", "Confirm and create vault"),
    (
        "디버거 연결이 감지되었거나 확인할 수 없어 잠갔습니다.",
        "Locked: a debugger was detected or could not be ruled out.",
    ),
    ("라이트", "Light"),
    ("먼저 15초간 보기를 눌러주세요.", "Press 'Show 15 s' first."),
    ("먼저 금고를 열어주세요.", "Open a vault first."),
    ("먼저 복사 허용을 켜주세요.", "Turn on 'Allow copy' first."),
    ("메모", "Notes"),
    ("메모 없음", "No notes"),
    (
        "미사용 시간이 지나 자동으로 잠갔습니다.",
        "Locked automatically after a period of inactivity.",
    ),
    (
        "금고 백업 파일 (.goyo) · '찾기'로 선택",
        "Vault backup file (.goyo) · choose it with 'Browse'",
    ),
    (
        "그 백업을 만들 때 쓰던 열쇠 파일",
        "The key file used when that backup was made",
    ),
    (
        "'금고 백업'으로 만든 파일을 새 금고 파일로 되살립니다. 백업을 만들 때 쓰던 열쇠 파일(또는 '열쇠 백업')과 그때의 비밀번호가 필요합니다.",
        "Brings a file made with 'Back up vault' back as a new vault file. It needs the key file used when the backup was made (or a 'Back up key' copy) and the password of that time.",
    ),
    ("백업 파일로 되살리기", "Restore from a backup file"),
    ("복사", "Copy"),
    ("복사 실패", "Copy failed"),
    (
        "복사 완료 · 15초 안에 붙여넣으세요. 복사 허용은 다시 꺼졌습니다.",
        "Copied · paste within 15 s. 'Allow copy' is off again.",
    ),
    ("복사 허용", "Allow copy"),
    (
        "복사 허용 중 · {}초 안에 복사하세요.",
        "Copy allowed · copy within {} s.",
    ),
    (
        "복사 허용: 클립보드 감시 프로그램이 복사한 값을 읽을 수 있습니다.",
        "Allow copy: clipboard monitors can read what you copy.",
    ),
    (
        "복사하려면 먼저 '복사 허용'을 켜세요.\n복사한 값은 앱을 전환해도 15초간 유지된 뒤 지워집니다.",
        "To copy, turn on 'Allow copy' first.\nA copied value stays 15 s, even across app switches, then is wiped.",
    ),
    (
        "복사한 값을 {}초 뒤 클립보드에서 지웁니다.",
        "The copied value is wiped from the clipboard in {} s.",
    ),
    ("복사할 항목을 선택하세요.", "Select an entry to copy."),
    (
        "복원 대상은 새 파일이어야 합니다.",
        "The restore target must be a new file.",
    ),
    (
        "복원할 백업 파일을 '찾기'로 선택하세요.",
        "Choose the backup to restore with 'Browse'.",
    ),
    (
        "되살린 금고를 저장할 새 위치",
        "New location for the restored vault",
    ),
    (
        "붙여넣기 실패: 길이 제한, 줄바꿈, 유니코드 형식 또는 클립보드 사용 상태를 확인하세요.",
        "Paste failed: check the length limit, line breaks, Unicode format or whether the clipboard is busy.",
    ),
    ("붙여넣기 크기 초과", "Paste is too large"),
    (
        "붙여넣기 형식 또는 길이 오류",
        "Paste format or length error",
    ),
    (
        "붙여넣은 값을 클립보드에서 지웠습니다. 다른 앱이 남긴 기록(Win+V 등)은 지우지 못합니다.",
        "The pasted value was wiped from the clipboard. History kept by other apps (Win+V etc.) is not wiped.",
    ),
    ("비밀번호", "Password"),
    ("비밀번호 · 12자 이상", "Password · 12+ characters"),
    ("비밀번호 변경", "Change password"),
    (
        "비밀번호를 바꾸고 금고를 새 열쇠로 다시 암호화했습니다.",
        "Password changed; the vault was encrypted again with a new key.",
    ),
    ("비밀번호 보기", "Show password"),
    ("비밀번호 숨기기", "Hide password"),
    ("비밀번호 키 생성 실패", "Could not derive the password key"),
    ("비밀번호 확인", "Confirm password"),
    ("비밀번호 확인 중입니다…", "Checking the password…"),
    (
        "비밀번호 확인이 일치하지 않습니다.",
        "The passwords do not match.",
    ),
    (
        "비밀번호·니모닉·프라이빗키를 암호화해 이 PC에 보관합니다.\n처음 사용한다면 새 금고를 만드세요.",
        "Keeps passwords, seed phrases and private keys encrypted on this PC.\nUsing it for the first time? Create a new vault.",
    ),
    ("비밀번호가 맞지 않습니다.", "Wrong password."),
    (
        "비밀번호는 12자 이상, UTF-8 1024바이트 이하로 입력하세요. 짧고 복잡한 암호보다 긴 문장이 안전합니다.",
        "Use at least 12 characters and at most 1024 UTF-8 bytes. A long phrase is safer than a short, complex password.",
    ),
    ("비밀정보", "Secret"),
    ("비밀정보 · 여러 줄 가능", "Secret · may span several lines"),
    (
        "비밀정보·메모 칸은 한글 IME를 차단합니다. 입력기 학습 위험이 있어 붙여넣기를 권장합니다.\r\n이 화면에서 복사·잘라내기는 막혀 있고 붙여넣기만 됩니다.",
        "The secret and notes fields block input methods (IME), which could learn what you type; paste instead.\r\nCopy and cut are blocked on this screen; only paste works.",
    ),
    ("삭제", "Delete"),
    (
        "삭제·수정 기록이 한도(65,536개)에 도달했습니다.",
        "The delete/edit record limit (65,536) was reached.",
    ),
    ("삭제할 항목을 선택하세요.", "Select an entry to delete."),
    ("새 OTP 6자리 · {tag}", "New OTP code · {tag}"),
    (
        "새 금고 등록을 다시 시작하세요.",
        "Start creating the vault again.",
    ),
    ("새 금고 만들기", "Create a new vault"),
    (
        "새 금고 만들기 · 백업 파일로 되살리기",
        "Create a new vault · Restore from a backup file",
    ),
    ("새 금고 파일", "New vault file"),
    (
        "새 금고를 만들었습니다. 아래 '열쇠 백업'으로 열쇠 파일 사본을 금고와 다른 곳에 두세요.",
        "Vault created. Use 'Back up key' below to keep a copy of the key away from the vault.",
    ),
    (
        "새 금고를 만들었습니다. 휴대폰 분실에 대비해 아래 'OTP 백업'으로 예비 기기에도 등록해 두세요.",
        "Vault created. In case you lose your phone, enroll a spare device with 'OTP backup' below.",
    ),
    (
        "새 금고와 열쇠 파일은 기존 파일을 덮어쓸 수 없습니다.",
        "The new vault and key files cannot overwrite existing files.",
    ),
    ("새 비밀번호 · 12자 이상", "New password · 12+ characters"),
    ("새 비밀번호 확인", "Confirm new password"),
    (
        "새 열쇠 파일 · 금고와 같은 폴더라 함께 도난당하면 비밀번호만 남습니다",
        "New key file · same folder as the vault: if both are taken, only the password is left",
    ),
    (
        "새 열쇠 파일 · 금고와 다른 곳(USB 등)에 두세요",
        "New key file · keep it away from the vault (e.g. a USB stick)",
    ),
    (
        "새 열쇠 파일 · 금고와 따로 보관하면 더 안전합니다",
        "New key file · safer kept apart from the vault",
    ),
    (
        "새 열쇠 파일 · 금고와 함께 클라우드 동기화 폴더에 있습니다",
        "New key file · in a cloud-synced folder together with the vault",
    ),
    (
        "새 열쇠 파일이 형식 검사를 통과하지 못해 쓰지 않았습니다.",
        "The new key file failed the format check, so it was not written.",
    ),
    (
        "새 파일 이름을 선택하세요 (기존 파일 덮어쓰기 금지)",
        "Choose a new file name (existing files are never overwritten)",
    ),
    ("새 항목", "New entry"),
    (
        "서버 사본이 새 버전 형식이라 동기화를 멈췄습니다. 고요 금고를 업데이트하세요.",
        "The server copy uses a newer format, so sync stopped. Update Goyo Vault.",
    ),
    (
        "서버 사본이 다른 금고의 것이라 무시했습니다. goyo-sync를 멈추고 동기화 폴더를 지운 뒤 다시 실행하세요.",
        "The server copy belongs to another vault and was ignored. Stop goyo-sync, delete the sync folder and start it again.",
    ),
    (
        "서버의 goyo-sync 스크립트가 이 금고 형식을 받지 않습니다. goyo-sync 설정 창에서 '서버에 설치·업데이트'를 누르세요. 변경은 이 PC에 저장되어 있습니다.",
        "The goyo-sync script on the server does not accept this vault's format. Press 'Install or update on server' in the goyo-sync settings window. Changes are kept on this PC.",
    ),
    (
        "서버의 열쇠 파일 기록과 이 PC의 금고 사본이 맞지 않아 서버가 업로드를 받지 않습니다(다른 PC가 열쇠를 바꿨거나 열쇠 파일 동기화를 껐음). 새 열쇠 파일을 받으면 다시 올라갑니다. 변경은 이 PC에 저장되어 있습니다.",
        "The server does not take the upload because its key file record does not match this PC's vault copy (another PC changed the keys or turned key-file sync off). Uploads resume once this PC has the new key file. Changes are kept on this PC.",
    ),
    (
        "서버에서 받은 금고를 인증하지 못해 무시했습니다(손상 또는 변조). 이 PC의 상태를 다시 올립니다.",
        "The copy from the server failed authentication and was ignored (damaged or altered). This PC uploads its state again.",
    ),
    (
        "선택한 항목을 삭제할까요? 기존 백업 사본은 삭제되지 않습니다.",
        "Delete the selected entry? Existing backups keep their copy.",
    ),
    ("수동으로 잠갔습니다.", "Locked."),
    ("수정", "Edit"),
    ("수정할 항목을 선택하세요.", "Select an entry to edit."),
    (
        "스캔이 안 되면 '설정 키 입력'에:",
        "Can't scan? Choose 'Enter a setup key':",
    ),
    ("시스템 시간을 확인하세요.", "Check the system clock."),
    ("아직 저장된 금고가 없습니다", "No vault yet"),
    (
        "아직 저장된 항목이 없습니다.\n'+ 새 항목'으로 첫 비밀정보를 추가하세요.",
        "No entries yet.\nAdd your first secret with '+ New entry'.",
    ),
    (
        "암호 자체 시험(HKDF)에 실패했습니다.",
        "The cryptographic self-test (HKDF) failed.",
    ),
    ("암호화 실패", "Encryption failed"),
    (
        "암호화된 열쇠를 백업했습니다. 금고와 분리하여 보관하세요.",
        "Encrypted key backed up. Keep it apart from the vault.",
    ),
    ("암호화된 항목\n(.goyo)", "Encrypted entries\n(.goyo)"),
    ("암호화하여 저장", "Save encrypted"),
    ("암호화하여 저장했습니다.", "Encrypted and saved."),
    (
        "압축 파일 안이나 임시 폴더에서 실행 중입니다. 이 폴더는 지워질 수 있으니, 계속 보관할 폴더에 압축을 푼 뒤 실행하세요.",
        "Running from inside a ZIP or a temporary folder, which may be deleted. Extract to a folder you will keep and run it from there.",
    ),
    ("앱에 표시된 6자리", "Code shown in the app"),
    ("연결 안 됨", "Offline"),
    ("열림 · {}", "Open · {}"),
    ("열림 · {} · {}", "Open · {} · {}"),
    ("열쇠 백업", "Back up key"),
    (
        "열쇠 백업 · 열쇠 파일 사본, 금고와 다른 곳에",
        "Key backup · kept apart from the vault",
    ),
    (
        "금고 백업 저장 · 항목이 담긴 금고 파일의 사본 (열려면 열쇠 파일과 비밀번호도 필요)",
        "Save vault backup · a copy of the vault file with your entries (it also needs the key file and password to open)",
    ),
    (
        "열쇠 백업 저장 · 열쇠 파일의 사본, 금고와 다른 곳(USB 등)에 보관",
        "Save key backup · a copy of the key file; keep it away from the vault (on a USB drive, for example)",
    ),
    (
        "열쇠 수정 번호가 한도에 닿았습니다. 새 금고를 만들어 항목을 옮기세요.",
        "The key file's change number has reached its limit. Create a new vault and move the entries there.",
    ),
    ("열쇠 파일", "Key file"),
    (
        "열쇠 파일 · 금고와 같은 폴더에 있습니다",
        "Key file · in the same folder as the vault",
    ),
    (
        "열쇠 파일 · 금고와 함께 클라우드 동기화 폴더에 있습니다",
        "Key file · in a cloud-synced folder together with the vault",
    ),
    (
        "열쇠 파일 이름을 되돌리지 못했습니다. 잠근 뒤 {temp}를 {name}(으)로 바꾸세요.",
        "Could not give the key file its name back. After locking, rename {temp} to {name}.",
    ),
    (
        "열쇠 파일과 금고 파일이 서로 다른 금고의 것입니다.",
        "The key file and the vault file belong to different vaults.",
    ),
    (
        "열쇠 파일은 비밀번호로 암호화되어 있습니다. 금고와 분리 보관하면 보호가 강화됩니다.\r\n분실한 비밀번호·열쇠·OTP를 우회하는 복구 기능은 없습니다.",
        "The key file is encrypted with your password; keeping it apart from the vault adds protection.\r\nThere is no recovery for a lost password, key file or OTP.",
    ),
    (
        "열쇠 파일의 제거 기록이 가득 찼습니다(480개). 더 이상 보안 키를 뺄 수 없습니다. 새 금고를 만들어 항목을 옮기세요.",
        "The key file's removal record is full (480). No more security keys can be removed. Create a new vault and move the entries there.",
    ),
    (
        "열쇠 파일을 찾을 수 없습니다. USB 등 다른 곳에 두었다면 '찾기'로 선택하세요. 다른 PC에서 가져온 금고라면 그 PC의 열쇠 파일을 USB로 가져오세요.",
        "Key file not found. If you keep it elsewhere (a USB drive, for example), choose it with 'Browse'. If this vault came from another PC, bring that PC's key file by USB.",
    ),
    (
        "열쇠 파일 {name}이(가) 보이지 않습니다. USB 등에 두었다면 꽂은 뒤 여세요. 다른 곳에 있으면 '찾기'로 고르세요.",
        "The key file {name} is not there. If you keep it on a USB drive, plug it in and open. If it is elsewhere, choose it with 'Browse'.",
    ),
    (
        "열쇠 파일이 이 PC에 없습니다. 다른 PC에서 가져온 금고라면 그 PC의 열쇠 파일을 USB로 가져와 이 금고 옆에 {name} 이름으로 두세요.",
        "The key file is not on this PC. If this vault came from another PC, bring that PC's key file by USB and put it next to this vault as {name}.",
    ),
    (
        "열쇠 파일 · 이 경로에 없습니다",
        "Key file · not at this path",
    ),
    (
        "파일을 고르는 창을 열지 못했습니다. 경로에 쓸 수 없는 문자가 있거나 폴더에 접근할 수 없을 수 있습니다. 다시 하거나 다른 폴더를 고르세요.",
        "The file dialog could not open. The path may hold characters it cannot take, or the folder may be out of reach. Try again or pick another folder.",
    ),
    (
        "열쇠 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.",
        "The key file was changed elsewhere. Lock and open the vault again.",
    ),
    (
        "열쇠 파일이 동기화 폴더 안에 있어 동기화하지 않습니다. 열쇠를 다른 폴더로 옮기세요.",
        "The key file is inside the sync folder, so this vault does not sync. Move the key file elsewhere.",
    ),
    (
        "열쇠 파일이 없어, 저장이 끊기며 남은 임시 파일로 엽니다.",
        "The key file is missing; opening with the temporary file an interrupted save left.",
    ),
    (
        "열쇠 파일이 변경되었습니다. 잠근 뒤 새 비밀번호로 다시 열고 백업하세요.",
        "The key file was changed. Lock, open it again with the new password and back up the key.",
    ),
    (
        "열지 않았습니다. 백업에서 복원이나 서버 기록을 확인하세요.",
        "Not opened. Restore from a backup or check the server history.",
    ),
    (
        "취소했습니다. 바뀐 것은 없습니다.",
        "Cancelled. Nothing was changed.",
    ),
    (
        "화면이 바뀌어 작업을 멈췄습니다. 바뀐 것은 없습니다.",
        "Stopped because the screen changed. Nothing was changed.",
    ),
    (
        "예비 기기에 등록한 뒤 '닫기'를 누르세요.",
        "Enroll the spare device, then press 'Close'.",
    ),
    (
        "예비 휴대폰이나 다른 OTP 앱에 등록하면 지금 휴대폰과 같은 번호가 나옵니다.",
        "A spare phone or another OTP app enrolled here shows the same codes as your phone.",
    ),
    (
        "예전 열쇠로 저장된 금고 파일을 새 열쇠로 다시 저장했습니다. 항목이 예상과 다르면 백업이나 서버 기록을 확인하세요.",
        "The vault file saved under an older key is saved again under the new key. If the entries are not what you expect, check your backups or the server history.",
    ),
    ("올리는 중", "Uploading"),
    (
        "올바르지 않은 유니코드 입력입니다.",
        "Invalid Unicode input.",
    ),
    ("올바르지 않은 파일 경로", "Invalid file path"),
    (
        "왼쪽 목록에서 항목을 선택하세요.",
        "Select an entry from the list on the left.",
    ),
    (
        "원격/공유 세션에서는 금고를 열 수 없습니다.",
        "A vault cannot be opened in a remote or shared session.",
    ),
    (
        "이 금고 옆에 동기화 폴더({})가 있습니다. goyo-sync가 이 폴더를 통해 암호화된 금고 사본만 서버와 주고받습니다. 열쇠 파일과 비밀번호는 보내지 않습니다.\n\n동기화를 켜면 금고 형식이 바뀌어 0.7 이하 버전에서는 이 금고와 이후 백업을 열 수 없습니다. 다른 PC도 먼저 0.8 이상으로 업데이트하세요. 동기화를 켤까요?",
        "There is a sync folder ({}) next to this vault. goyo-sync uses it to exchange only an encrypted copy of the vault with your server. The key file and password are never sent.\n\nTurning sync on changes the vault format: version 0.7 and older cannot open this vault or later backups of it. Update your other PCs to 0.8 or later first. Turn sync on?",
    ),
    (
        "이 금고 옆에 동기화 폴더({})가 있습니다. goyo-sync가 이 폴더를 통해 암호화된 금고 사본만 서버와 주고받습니다. 열쇠 파일과 비밀번호는 보내지 않습니다.\n\n이 금고는 열쇠를 바꾼 적이 있어 0.8 이하 버전에서는 열 수 없고, 0.8 서버 스크립트는 이 금고의 사본을 받지 않습니다. 동기화를 켜기 전에 서버 스크립트를 먼저, 그다음 다른 PC의 고요 금고와 goyo-sync를 0.9.0 이상으로 업데이트하세요. 동기화를 켤까요?",
        "There is a sync folder ({}) next to this vault. goyo-sync uses it to exchange only an encrypted copy of the vault with your server. The key file and password are never sent.\n\nThe keys of this vault were changed, so version 0.8 and older cannot open it, and a 0.8 server script does not accept its copies. Before turning sync on, update the server script first, then Goyo Vault and goyo-sync on your other PCs, to 0.9.0 or later. Turn sync on?",
    ),
    (
        "이 금고 파일은 보안 키로 잠긴 열쇠 파일로 저장되었습니다. 이 고요 금고 빌드에는 보안 키 기능이 없어 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다.",
        "This vault file was saved with a key file locked by a security key. This Goyo Vault build has no security-key support, so it cannot open it. Your password is not wrong.",
    ),
    (
        "이 금고 파일은 이 열쇠 파일에 없는 열쇠로 저장되어 있습니다. 이 금고를 마지막으로 연 열쇠 파일을 선택하세요. 다른 PC에서 열쇠를 바꿨다면 이 PC의 원래 열쇠 파일로 연 뒤 '열쇠 관리 › 새 열쇠 파일 받기'로 새 열쇠 파일을 받으세요.",
        "This vault file is saved under a key that is not in this key file. Choose the key file that last opened this vault. If the key was changed on another PC, open the vault with this PC's own key file and then take the new key file with 'Key management › Receive a new key file'.",
    ),
    (
        "이 금고 파일은 이 열쇠 파일의 형식으로 다시 저장하면 용량 제한(8 MiB)을 넘어 열지 않았습니다. 비밀번호가 틀린 것이 아닙니다. 이 금고의 예전 열쇠 파일(0.8 형식)이 있으면 그것으로 열어 항목을 줄인 뒤 다시 여세요.",
        "This vault file was not opened: saved again in this key file's format, it would exceed the size limit (8 MiB). Your password is not wrong. If you still have this vault's earlier key file (0.8 format), open it with that one, remove entries, then open it again.",
    ),
    (
        "이 금고 파일은 이 PC의 열쇠 파일보다 새로운 열쇠 파일로 저장되었습니다. 다른 PC에서 이 금고의 열쇠 파일을 바꾼 것으로 보입니다. 그 열쇠 파일을 USB로 가져와 '열쇠 관리 › 새 열쇠 파일 받기'로 받으세요. 그 전에는 이 PC에서 열쇠를 바꾸지 마세요.",
        "This vault file was saved with a newer key file than this PC's. The vault's key file seems to have been changed on another PC. Bring that key file over by USB and take it with 'Key management › Receive a new key file'. Do not change the key on this PC before that.",
    ),
    (
        "이 금고 파일은 이 열쇠 파일의 예전 열쇠로 저장되어 있습니다.\n다른 PC에서 열쇠를 바꾼 뒤 이 PC에서 처음 여는 것이라면 정상입니다(같은 열쇠 파일을 함께 쓰거나 새 열쇠 파일을 옮겨 온 경우).\n그런 일이 없었다면 예전 열쇠를 가진 누군가가 금고 파일을 바꿔 넣었을 수 있습니다. 그 경우 '아니요'를 누르고 백업이나 서버 기록을 확인하세요.\n이 파일을 열고 새 열쇠로 다시 저장할까요?",
        "This vault file is saved under an older key of this key file.\nThat is normal if this PC opens it for the first time after the key was changed on another PC (sharing one key file, or with the new key file carried over).\nIf nothing like that happened, someone holding the old key may have swapped the vault file. In that case press 'No' and check your backups or the server history.\nOpen this file and save it again under the new key?",
    ),
    (
        "이 금고는 OTP를 쓰지 않습니다.",
        "This vault does not use an OTP.",
    ),
    (
        "이 백업은 이 열쇠 파일에 없는 열쇠로 잠겨 있습니다. 그 백업을 만들 때의 열쇠 파일 사본으로 복원하세요.",
        "This backup is locked with a key that is not in this key file. Restore it with the copy of the key file from when the backup was made.",
    ),
    (
        "이 열쇠 파일은 OTP를 씁니다. 휴대폰 OTP 앱의 6자리도 입력하세요.",
        "This key file uses an OTP. Also enter the 6-digit code from your phone.",
    ),
    (
        "이 열쇠 파일은 보안 키(YubiKey 등)가 있어야 열립니다. 지금 쓰는 고요 금고는 보안 키 기능이 빠진 기본 빌드라 이 파일을 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다. 보안 키 기능은 아직 실험 단계라 직접 빌드해야 합니다(docs/SECURITY_KEY.md).",
        "This key file opens only with a security key (YubiKey or similar). This Goyo Vault is the default build without security-key support, so it cannot open this file. Your password is not wrong. Security-key support is still experimental and has to be built yourself (docs/SECURITY_KEY.md).",
    ),
    (
        "이 열쇠 파일은 보안 키(YubiKey 등)가 있어야 열립니다. 지금 쓰는 고요 금고는 보안 키 기능이 빠진 기본 빌드라 이 파일을 열 수 없습니다. 비밀번호가 틀린 것이 아닙니다. 보안 키 기능은 아직 실험 단계라 직접 빌드해야 합니다(docs/SECURITY_KEY.md). 파일이 손상되었거나 더 새로운 버전에서 만든 파일일 수도 있습니다.",
        "This key file opens only with a security key (YubiKey or similar). This Goyo Vault is the default build without security-key support, so it cannot open this file. Your password is not wrong. Security-key support is still experimental and has to be built yourself (docs/SECURITY_KEY.md). The file may also be damaged, or made by a newer version.",
    ),
    ("이름 · 목록에 표시됩니다", "Name · shown in the list"),
    (
        "이름과 비밀정보를 입력하세요.",
        "Enter a name and the secret.",
    ),
    (
        "인증 및 암호화 처리 중입니다…",
        "Authenticating and encrypting…",
    ),
    (
        "인증 실패 후 대기 중입니다. 잠시 후 다시 시도하세요.",
        "Waiting after a failed attempt. Try again in a moment.",
    ),
    (
        "인증 실패. 잠시 후 다시 시도하세요.",
        "Authentication failed. Try again in a moment.",
    ),
    (
        "인증 실패: 비밀번호·열쇠·새 OTP·시스템 시간과 파일 상태를 확인하세요.",
        "Authentication failed: check the password, key file, a fresh OTP code, the clock and the files.",
    ),
    (
        "일반 파일 경로를 지정하세요. 스트림·끝 공백·끝 점은 허용하지 않습니다.",
        "Choose a regular file path. Streams and trailing spaces or dots are not allowed.",
    ),
    (
        "임시 암호화 파일 생성 실패",
        "Could not create the encrypted temporary file",
    ),
    (
        "입력 보호 설정 실패. 프로그램을 다시 시작하고 Windows 입력기를 확인하세요.",
        "Input protection failed. Restart the program and check the Windows input method.",
    ),
    (
        "입력 보호 설정 실패로 저장/인증을 중단합니다.",
        "Input protection failed, so saving and unlocking are stopped.",
    ),
    (
        "입력 보호 설정 실패로 저장을 중단합니다.",
        "Input protection failed, so saving is stopped.",
    ),
    (
        "입력 보호를 확인할 수 없어 비밀번호를 표시하지 않았습니다.",
        "Input protection could not be confirmed, so the password stays hidden.",
    ),
    ("자동 잠금", "Auto-lock"),
    (
        "자동 잠금 1분: 1분 동안 쓰지 않거나 다른 앱에 30초 넘게 머무르면 잠급니다.",
        "Auto-lock 1 min: locks after 1 minute without use or 30 seconds in another app.",
    ),
    (
        "자동 잠금 30분: 30분 동안 쓰지 않으면 잠급니다. 다른 앱에 있는 시간도 포함됩니다.",
        "Auto-lock 30 min: locks after 30 minutes without use, time in other apps included.",
    ),
    (
        "자동 잠금 5분: 5분 동안 쓰지 않으면 잠급니다. 다른 앱에 있는 시간도 포함됩니다.",
        "Auto-lock 5 min: locks after 5 minutes without use, time in other apps included.",
    ),
    (
        "자동 잠금 끔: 잠금 버튼, Windows 화면 잠금(Win+L), 절전, 종료 때만 잠깁니다. 자리를 비울 때는 Win+L을 누르세요.",
        "Auto-lock off: locks only with Lock, the Windows screen lock (Win+L), sleep or shutdown. Press Win+L when you step away.",
    ),
    (
        "자동 잠금 타이머를 시작할 수 없어 종료합니다.",
        "Cannot start the auto-lock timer; exiting.",
    ),
    ("잠금", "Lock"),
    ("잠금 해제", "Unlock"),
    (
        "잠금 해제됨 · 자동 잠금이 꺼져 있습니다. 자리를 비울 때는 잠금 버튼이나 Win+L을 누르세요.",
        "Unlocked · auto-lock is off. Press Lock or Win+L when you step away.",
    ),
    (
        "잠금 해제됨 · 저장하면 즉시 암호화됩니다. 화면 캡처는 막지만 악성코드까지 막지는 못합니다.",
        "Unlocked · changes are encrypted as soon as you save. Hidden from capture, but this cannot stop malware.",
    ),
    ("잠김", "Locked"),
    (
        "저장 실패: 디스크 공간과 권한을 확인하세요.",
        "Save failed: check disk space and permissions.",
    ),
    (
        "저장할 폴더가 없습니다.",
        "The folder to save in does not exist.",
    ),
    ("절전 전환으로 잠갔습니다.", "Locked for sleep."),
    (
        "종료 중 · 클립보드 지우기를 확인하고 있습니다.",
        "Exiting · making sure the clipboard is wiped.",
    ),
    ("종료 중입니다.", "Exiting."),
    ("종류", "Type"),
    ("종류 없음", "No type"),
    (
        "주의: 금고와 열쇠가 모두 클라우드 동기화 폴더에 있어, 그 계정이 털리면 비밀번호만 남습니다. 열쇠는 동기화되지 않는 곳에 두세요.",
        "Warning: the vault and key are both in a cloud-synced folder; if that account is breached, only the password is left. Keep the key where it is not synced.",
    ),
    (
        "주의: 열쇠 파일이 금고와 같은 폴더에 있어, 폴더째 가져간 사람은 비밀번호만 알아내면 됩니다. '열쇠 백업'으로 USB 등에 옮기고 원래 열쇠는 지우세요.",
        "Warning: the key file is in the vault's folder, so whoever takes the folder only needs your password. Copy it to a USB stick with 'Back up key' and delete the original.",
    ),
    (
        "지난 열쇠 변경을 마저 끝내 금고 파일을 새 열쇠로 다시 저장했습니다.",
        "The last key change is now finished: the vault file is saved again under the new key.",
    ),
    (
        "창을 선택하면\nQR이 다시 보입니다",
        "Select this window\nto show the QR again",
    ),
    ("찾기", "Browse"),
    (
        "최대 1000개까지 저장할 수 있습니다.",
        "Up to 1000 entries can be stored.",
    ),
    ("취소", "Cancel"),
    (
        "캡처 차단, 세션 잠금 감시 또는 메시지 필터를 설정할 수 없어 종료합니다.",
        "Cannot set up capture protection, session lock monitoring or the message filter; exiting.",
    ),
    (
        "캡처 차단이 적용되지 않아 금고를 잠갔습니다.",
        "Locked: screen-capture protection is not in effect.",
    ),
    (
        "켜 두면 비밀번호가 새어도 휴대폰 없이는 이 앱으로 금고를 열 수 없습니다.\r\n금고를 열 때마다 휴대폰 OTP 앱의 6자리를 함께 입력합니다.\r\n금고·열쇠 파일을 통째로 복사해 가는 것은 막지 못하니, 열쇠 파일은 따로 두세요.",
        "With it on, a leaked password cannot open the vault in this app without your phone.\r\nEach time you open the vault, you also enter the 6-digit code from the OTP app.\r\nIt cannot stop someone copying both vault and key files, so keep the key apart.",
    ),
    (
        "켜기 권장\n켠 금고만 필요",
        "Recommended;\nonly if turned on",
    ),
    ("끔", "Off"),
    (
        "클립보드 기록 제외 설정 실패",
        "Could not exclude the copy from clipboard history",
    ),
    ("클립보드 사용 중", "Clipboard in use"),
    ("클립보드 읽기 실패", "Could not read the clipboard"),
    (
        "클립보드 정리 후 종료를 기다리고 있습니다.",
        "Waiting to exit until the clipboard is wiped.",
    ),
    (
        "클립보드를 비울 수 없습니다.",
        "Cannot clear the clipboard.",
    ),
    ("클립보드를 지우는 중입니다.", "Wiping the clipboard."),
    ("텍스트 형식 오류", "Text format error"),
    ("텍스트가 없습니다.", "No text."),
    ("파일 경로를 지정하세요.", "Choose a file path."),
    (
        "편집 중 내용이 화면에 보입니다. 30분 동안 쓰지 않으면 잠기고 저장하지 않은 내용은 지워집니다.",
        "What you edit is visible. After 30 minutes without use the vault locks and unsaved changes are lost.",
    ),
    (
        "편집 중 내용이 화면에 보입니다. 5분 동안 쓰지 않으면 잠기고 저장하지 않은 내용은 지워집니다.",
        "What you edit is visible. After 5 minutes without use the vault locks and unsaved changes are lost.",
    ),
    (
        "편집 중 내용이 화면에 보입니다. 다른 앱에 30초 넘게 머무르면 잠기고 저장하지 않은 내용은 지워집니다.",
        "What you edit is visible. After 30 s in another app the vault locks and unsaved changes are lost.",
    ),
    (
        "편집 중 내용이 화면에 보입니다. 잠금·화면 잠금·절전 때 저장하지 않은 내용은 지워집니다.",
        "What you edit is visible. Locking, the Windows screen lock and sleep clear unsaved changes.",
    ),
    (
        "파일 교체가 끊겨 임시 파일(.goyotmp)을 남겼습니다. 다음에 열 때 자동으로 복구합니다.",
        "Replacing the file was cut off, so its temporary file (.goyotmp) was kept. The next unlock recovers it automatically.",
    ),
    ("파일 선택", "Choose a file"),
    ("파일 식별 실패", "Could not identify the file"),
    ("파일 읽기 실패", "Could not read the file"),
    (
        "파일 잠금을 만들 수 없습니다.",
        "Could not create the file lock.",
    ),
    (
        "파일 저장/교체 실패: 기존 파일, 저장장치 연결과 쓰기 권한을 확인하세요.",
        "Could not save or replace the file: check existing files, the drive connection and write permission.",
    ),
    ("파일 정보 오류", "File information error"),
    ("파일 크기 제한 초과", "File size limit exceeded"),
    ("파일을 열 수 없습니다.", "Cannot open the file."),
    (
        "파일이 없고, 저장이 끊기며 남은 임시 파일(.goyotmp)이 같은 폴더에 있습니다. 지우지 마세요. 그 파일 이름을 원래 이름으로 바꾸면 복구될 수 있습니다.",
        "The file is missing, and a temporary file (.goyotmp) left by an interrupted save is in the same folder. Do not delete it; renaming it to the original name may recover the vault.",
    ),
    (
        "표시할 글자가 화면 너비를 초과합니다.",
        "The text is too wide to display.",
    ),
    ("프라이빗키", "Private key"),
    (
        "프로그램 폴더가 클라우드 동기화 폴더에 있습니다. 여기에 금고와 열쇠를 함께 두면 둘 다 같은 계정에 올라갑니다.",
        "The program folder is in a cloud-synced folder. A vault and key kept here together both upload to the same account.",
    ),
    (
        "프로세스 보호 설정에 실패했습니다.",
        "Could not set up process protection.",
    ),
    (
        "합치면 항목 1000개 또는 8 MiB를 넘어 합치지 않았습니다. 항목을 정리하세요.",
        "Merging would exceed 1000 entries or 8 MiB, so nothing was merged. Remove some entries.",
    ),
    ("항목 ID 오류", "Entry ID error"),
    ("항목 {count}개", "Entries: {count}"),
    ("항목 선택 오류", "Entry selection error"),
    ("항목 수 제한 초과", "Too many entries"),
    ("항목 수정", "Edit entry"),
    ("항목을 삭제했습니다.", "Entry deleted."),
    ("항목을 선택하세요.", "Select an entry."),
    ("항목이 너무 깁니다.", "The entry is too long."),
    (
        "본인 확인: 현재 비밀번호",
        "Verify it's you: current password",
    ),
    (
        "현재 비밀번호를 확인한 뒤 새 열쇠로 금고를 다시 암호화합니다.",
        "Checks the current password, then encrypts the vault again with a new key.",
    ),
    (
        "현재 비밀번호와 새 OTP 번호를 확인한 뒤 새 열쇠로 금고를 다시 암호화합니다.",
        "Checks the current password and a fresh OTP code, then encrypts the vault again with a new key.",
    ),
    (
        "새 데이터 키로 금고를 다시 암호화하고 새 열쇠 파일을 씁니다. 예전 열쇠 파일과 예전 비밀번호로는 앞으로 저장하는 내용을 열 수 없습니다. 바꾼 뒤 새 열쇠 파일을 백업하세요.",
        "The vault is encrypted again with a new data key, and a new key file is written. The old key file and old password cannot open what you save from now on. Back up the new key file after the change.",
    ),
    (
        "현재 화면에서 허용되지 않는 작업입니다.",
        "That action is not available on this screen.",
    ),
    (
        "화면 글자 크기를 측정할 수 없습니다.",
        "Cannot measure the text size.",
    ),
    (
        "화면 또는 시스템 세션 변경으로 잠갔습니다.",
        "Locked: the screen or system session changed.",
    ),
    (
        "화면 보호 상태를 확인할 수 없습니다.",
        "Cannot check the screen protection state.",
    ),
    ("화면 생성 실패", "Could not create the window"),
    ("화면 작업 중입니다.", "The window is busy."),
    ("화면 초기화 실패", "Could not initialize the window"),
    ("화면이 닫혔습니다.", "The window was closed."),
    ("확인 · 새 파일로 복원", "Restore to a new file"),
    (
        "확인한 뒤에 금고 파일이 바뀌어 열지 않았습니다. 다시 열어 보세요. 그런 일이 없었다면 누군가 금고 파일을 바꿔 넣었을 수 있으니 백업이나 서버 기록을 확인하세요.",
        "The vault file changed after you confirmed it, so it was not opened. Try opening it again. If nothing like that happened, someone may have swapped the vault file: check your backups or the server history.",
    ),
    ("휴대폰 OTP", "Phone OTP"),
    ("휴대폰 OTP 등록 · {tag}", "Enroll your phone · {tag}"),
    (
        "휴대폰 OTP 앱으로 QR을 등록하고, 앱에 표시된 6자리를 입력하세요.",
        "Scan the QR with your phone's OTP app, then enter the 6-digit code it shows.",
    ),
    (
        "휴대폰 OTP로 한 번 더 잠그기",
        "Add a second lock: phone OTP",
    ),
    (
        "휴대폰을 잃어도 금고를 열 수 있도록, 지금 쓰는 OTP를 예비 휴대폰이나\r\n다른 OTP 앱에도 등록해 둡니다. 휴대폰을 잃은 뒤에는 이 화면을 열 수 없습니다.",
        "So you can still open the vault if you lose your phone, enroll this OTP on a spare\r\nphone or another OTP app too. Once the phone is lost, this screen cannot be opened.",
    ),
    (
        "휴대폰을 잃으면 금고를 열 수 없으니 예비 기기에도 등록해 두세요.\r\n금고를 연 뒤 아래쪽 'OTP 백업'에서 이 QR을 다시 볼 수 있습니다.",
        "Lose the phone and the vault cannot be opened, so enroll a spare device too.\r\nOnce the vault is open, 'OTP backup' at the bottom shows this QR again.",
    ),
    (
        "흔한 단어(password, dragon 등)·키보드 배열·연속된 숫자는 추측 도구가 가장 먼저 시도해서 글자 수로 치지 않습니다. 흔하지 않은 단어나 나만 아는 문장을 섞으세요.",
        "Common words (password, dragon, ...), keyboard runs and number sequences are tried first by guessing tools, so they do not count. Add uncommon words or a phrase only you know.",
    ),
    // goyo-sync.exe settings window (src/bin/goyo-sync/gui.rs).
    ("고요 금고 동기화", "Goyo Vault Sync"),
    (
        "SSH 개인 키 (모든 파일)\0*.*\0",
        "SSH private key (all files)\0*.*\0",
    ),
    ("전용 SSH 키 파일 선택", "Choose the dedicated SSH key file"),
    ("서버 (ssh 호스트)", "Server (ssh host)"),
    ("고급 설정", "Advanced settings"),
    ("연결 확인", "Check connection"),
    ("서버에 설치·업데이트", "Install or update on server"),
    (
        "~/.ssh/config의 별칭(예: my-server)이나 user@host를 적습니다. 집 밖에서는 ssh 포트를 인터넷에 열지 말고 Tailscale 같은 VPN으로 서버에 닿게 하세요.",
        "An alias from ~/.ssh/config (for example my-server) or user@host. Away from home, never open the ssh port to the internet; reach the server through a VPN such as Tailscale.",
    ),
    ("서버의 스크립트 경로", "Script path on the server"),
    ("파이썬 명령", "Python command"),
    ("간격(초)", "Interval (s)"),
    ("제한(초)", "Timeout (s)"),
    (
        "전용 SSH 키 파일 (선택) · 비우면 평소 ssh 설정을 씁니다",
        "Dedicated SSH key file (optional) · empty: your usual ssh setup",
    ),
    ("금고", "Vaults"),
    (
        "동기화할 금고 파일 · 최대 8개",
        "Vault files to sync · up to 8",
    ),
    ("이 PC로 가져오기…", "Bring to this PC…"),
    ("빼기", "Remove"),
    ("추가…", "Add…"),
    (
        "Windows에 로그인하면 자동으로 시작",
        "Start automatically when I sign in to Windows",
    ),
    ("저장하고 시작", "Save and start"),
    ("지금 동기화", "Sync now"),
    ("중지", "Stop"),
    ("로그 보기", "View log"),
    ("로그", "Log"),
    (
        "goyo-sync.log의 최근 {}줄",
        "Recent lines of goyo-sync.log: {}",
    ),
    ("새로 고침", "Refresh"),
    ("아직 로그가 없습니다.", "No log yet."),
    ("이 PC로 가져오기", "Bring to this PC"),
    (
        "가져올 금고를 고르세요. 태그는 OTP 앱에 보이는 'Goyo Vault (태그)'의 태그와 같습니다.",
        "Choose the vault to bring. Its tag is the one your OTP app shows as 'Goyo Vault (tag)'.",
    ),
    (
        "고른 폴더에 금고 파일(vault.goyo)로 저장하고 동기화 목록에 넣습니다. 그다음 할 일은 가져온 뒤 알려 드립니다.",
        "It is saved as a vault file (vault.goyo) in the folder you choose and added to the sync list. What to do next is shown once it is here.",
    ),
    ("받기…", "Get…"),
    ("가져오기…", "Bring it here…"),
    (
        "고요 금고 (*.goyo)\0*.goyo\0모든 파일\0*.*\0",
        "Goyo vault (*.goyo)\0*.goyo\0All files\0*.*\0",
    ),
    (
        "가져올 폴더를 고르세요 · 금고는 그 폴더에 이 이름으로 저장됩니다",
        "Choose the folder to bring it to · the vault is saved there under this name",
    ),
    (
        "goyo-sync의 동기화 목록에 넣었습니다. 이 창의 '저장하고 시작'을 누르면 이 PC에서도 동기화가 시작됩니다.",
        "It was added to goyo-sync's sync list. Press 'Save and start' in this window to start syncing it on this PC too.",
    ),
    (
        "동기화 목록에는 넣지 못했습니다: {} 필요하면 '추가…'로 넣으세요.",
        "It could not be added to the sync list: {} Add it with 'Add…' if needed.",
    ),
    (
        "('열쇠 관리'의 열쇠 확인 코드와는 다른 코드입니다.)",
        "(This is not the key check code of 'Key management'.)",
    ),
    (
        "고요 금고를 열면 이 금고로 바로 이어집니다.",
        "open Goyo Vault: it goes straight to this vault.",
    ),
    (
        "고요 금고의 '금고 파일 열기'(또는 로그인 화면의 '찾기')로 이 파일을 고르세요.",
        "in Goyo Vault, choose this file with 'Open a vault file' (or 'Browse' on the login screen).",
    ),
    (
        "전용 SSH 키 파일을 다른 계정도 읽을 수 있어 ssh가 그 키를 쓰지 않았습니다. 내 계정만 읽게 고친 뒤 '연결 확인'을 누르세요.",
        "Other accounts can read the dedicated SSH key file, so ssh did not use that key. Let only your account read it, then press 'Check connection'.",
    ),
    (
        "ssh가 전용 SSH 키 파일을 쓰지 않았습니다. 이 PC의 다른 계정도 그 파일을 읽을 수 있게 되어 있기 때문입니다(Windows OpenSSH: bad permissions). 그대로 두면 ssh가 다른 키로 접속해 서버의 강제 명령(동기화만 허용, 열쇠 파일 동기화 --key-sync)이 적용되지 않으므로, goyo-sync는 그 연결을 쓰지 않습니다.\n\nPowerShell에서 다음 두 줄로 고친 뒤 '연결 확인'을 다시 누르세요(상속된 권한을 지우고 내 계정만 남깁니다):\n\nicacls \"{}\" /inheritance:r\nicacls \"{}\" /grant:r \"$($env:USERNAME):F\"\n\n파일 속성 > 보안에서 내 계정 말고 다른 항목(Users, Everyone 등)이 남아 있으면 지우세요.",
        "ssh did not use the dedicated SSH key file, because other accounts of this PC can read it (Windows OpenSSH: bad permissions). Left like that, ssh logs in with another key, outside the server's forced command (sync only, key-file sync --key-sync), so goyo-sync does not use that connection.\n\nFix it with these two lines in PowerShell, then press 'Check connection' again (they remove the inherited permissions and keep only your account):\n\nicacls \"{}\" /inheritance:r\nicacls \"{}\" /grant:r \"$($env:USERNAME):F\"\n\nIf the file's Properties > Security still lists anything but your account (Users, Everyone and so on), remove it.",
    ),
    (
        "가져왔습니다: {}\n(서버 버전 {}, {}바이트)\n\n{}이 금고를 열려면 열쇠 파일이 필요합니다. 다른 PC의 열쇠 파일(.goyokey)을 USB로 복사해 이 폴더에 {} 이름으로 넣으세요:\n{}\n\n다음 순서:\n1. {}\n2. 열쇠 파일을 넣은 뒤 {}\n3. 처음 받는 사본은 서버를 믿는 것이니, 연 뒤 고요 금고 아래쪽 상태 줄의 '동기화됨 · 확인 코드 …'를 첫 PC의 것과 비교하세요.{}",
        "Brought here: {}\n(server version {}, {} bytes)\n\n{}To open this vault you need its key file. Copy the key file (.goyokey) of another PC by USB into this folder, named {}:\n{}\n\nNext:\n1. {}\n2. Once the key file is there, {}\n3. A first copy from the server trusts the server: after opening it, compare 'Synced · check code …' on Goyo Vault's status line at the bottom with the first PC's.{}",
    ),
    (
        "서버 호스트 키가 이 PC의 known_hosts에 저장된 키와 다릅니다.\n\n누군가 연결을 가로채고 있을 수 있어 goyo-sync는 연결하지 않으며, 이 창에서는 새 키를 받아들이지 않습니다.\n\n서버를 다시 설치했거나 키를 바꾼 것이 확실할 때만: 서버에서 직접 지문을 확인하고(예: ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub), PowerShell에서 ssh-keygen -R {} 으로 예전 키를 지운 뒤 ssh {} 로 한 번 접속해 지문을 비교하세요.",
        "The server's host key differs from the key stored in this PC's known_hosts.\n\nSomeone may be intercepting the connection, so goyo-sync does not connect, and this window never accepts the new key.\n\nOnly if you are sure the server was reinstalled or its key changed: check the fingerprint on the server itself (for example ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub), remove the old key with ssh-keygen -R {} in PowerShell, then connect once with ssh {} and compare the fingerprint.",
    ),
    ("백그라운드 동기화 실행 중", "Background sync running"),
    ("백그라운드 동기화 꺼짐", "Background sync off"),
    (
        "아직 동기화할 금고가 없습니다. 이 PC의 금고는 '추가…'로 고르고, 다른 PC의 금고는 '이 PC로 가져오기…'로 가져오세요.",
        "No vault to sync yet. Choose a vault of this PC with 'Add…', or bring another PC's vault with 'Bring to this PC…'.",
    ),
    (
        "서버를 적고 '연결 확인'을 누르세요. 서버에 스크립트가 아직 없다면 먼저 '서버에 설치·업데이트'를 누르세요.",
        "Enter the server and press 'Check connection'. If the server has no script yet, press 'Install or update on server' first.",
    ),
    ("연결 확인 중… {}초", "Checking the connection… {} s"),
    (
        "호스트 키를 저장하고 연결 확인 중… {}초",
        "Storing the host key and checking… {} s",
    ),
    ("서버에 설치하는 중… {}초", "Installing on the server… {} s"),
    (
        "서버의 금고 목록을 받는 중… {}초",
        "Getting the server's vault list… {} s",
    ),
    (
        "서버에서 금고를 가져오는 중… {}초",
        "Bringing the vault from the server… {} s",
    ),
    (
        "모든 금고를 지금 동기화하는 중… {}초",
        "Syncing every vault now… {} s",
    ),
    (
        "백그라운드 동기화를 다시 시작하는 중… {}초",
        "Restarting background sync… {} s",
    ),
    (
        "연결 정상 · 512바이트 이진 왕복 확인 · 서버에 금고 {}개",
        "Connection OK · 512-byte binary round trip checked · vaults on the server: {}",
    ),
    (
        "서버 호스트 키가 known_hosts와 다릅니다. 중간자 공격일 수 있어 연결하지 않습니다.",
        "The server's host key differs from known_hosts. This may be an attack, so goyo-sync will not connect.",
    ),
    (
        "서버가 known_hosts에 있는 키와 다른 종류의 키를 보냈습니다. 연결하지 않습니다.",
        "The server sent another type of host key than the one in known_hosts. goyo-sync will not connect.",
    ),
    (
        "호스트 키를 확인할 수 없습니다. PowerShell에서 ssh {}로 한 번 접속해 지문을 확인하세요.",
        "The host key cannot be checked. Connect once with ssh {} in PowerShell and check the fingerprint.",
    ),
    (
        "호스트 키를 저장하지 않았습니다. 지문을 확인할 수 있을 때 다시 '연결 확인'을 누르세요.",
        "The host key was not stored. Press 'Check connection' again when you can check the fingerprint.",
    ),
    (
        "서버에 스크립트를 설치했습니다(selftest: PASS). 이제 '연결 확인'을 누르세요.",
        "The script is installed on the server (selftest: PASS). Now press 'Check connection'.",
    ),
    (
        "설치는 됐지만 서버 셸이 PASS 외의 글을 출력합니다. 셸 시작 파일이 대화형 셸에서만 출력하게 고치세요.",
        "Installed, but the server's shell prints text besides PASS. Make the shell start-up files print only in interactive shells.",
    ),
    (
        "서버에서 파이썬 명령({})을 찾지 못했습니다. 고급 설정의 파이썬 명령을 확인하세요.",
        "The server did not find the Python command ({}). Check it under Advanced settings.",
    ),
    (
        "설치하지 못했습니다. 서버 출력: {}",
        "Installation failed. Server output: {}",
    ),
    (
        "스크립트 경로나 파이썬 명령을 설치 명령에 쓸 수 없습니다. 스크립트 경로는 파일 이름으로 끝나야 합니다.",
        "The script path or Python command cannot go into the install command. The script path must end in a file name.",
    ),
    (
        "서버에 금고가 없습니다. 첫 PC의 고요 금고에서 동기화를 켜면 올라갑니다.",
        "The server has no vaults yet. They appear once sync is on in Goyo Vault on the first PC.",
    ),
    (
        "가져왔습니다(서버 버전 {}, {}바이트). 안내대로 '저장하고 시작'을 누르고 고요 금고를 여세요.",
        "Brought here (server version {}, {} bytes). As described, press 'Save and start' and open Goyo Vault.",
    ),
    (
        "그 이름의 파일이나 동기화 폴더가 이미 있습니다. 덮어쓰지 않으니 다른 폴더를 고르세요.",
        "A file or sync folder of that name already exists and is never overwritten. Choose another folder.",
    ),
    (
        "서버에 그 금고가 없습니다.",
        "The server does not have that vault.",
    ),
    (
        "파일을 저장할 수 없습니다. 다른 폴더나 이름을 고르세요.",
        "Cannot save the file. Choose another folder or name.",
    ),
    (
        "아직 설정이 저장되지 않았습니다. 서버와 금고를 정한 뒤 '저장하고 시작'을 누르세요.",
        "Nothing is saved yet. Set the server and vaults, then press 'Save and start'.",
    ),
    (
        "저장하지 않은 변경이 있습니다. '저장하고 시작'을 누르면 적용됩니다.",
        "There are unsaved changes. 'Save and start' applies them.",
    ),
    (
        "백그라운드에서 동기화하고 있습니다. 이 창을 닫아도 계속됩니다.",
        "Syncing in the background. It keeps going when you close this window.",
    ),
    (
        "백그라운드 동기화가 꺼져 있습니다. '저장하고 시작'으로 켜세요.",
        "Background sync is off. Turn it on with 'Save and start'.",
    ),
    (
        "goyo-sync.conf를 읽을 수 없습니다. 설정을 다시 저장하세요.",
        "Cannot read goyo-sync.conf. Save the settings again.",
    ),
    (
        "goyo-sync.conf {}번째 줄에 문제가 있습니다. 보이는 설정을 고친 뒤 '저장하고 시작'을 누르세요.",
        "Line {} of goyo-sync.conf has a problem. Fix the settings shown and press 'Save and start'.",
    ),
    (
        "설정을 저장하고 백그라운드 동기화를 시작했습니다.",
        "Settings saved; background sync started.",
    ),
    (
        "실행 중인 도우미가 멈추지 않아 다시 시작하지 못했습니다. 잠시 뒤 다시 누르세요.",
        "The running helper did not stop, so it was not restarted. Try again in a moment.",
    ),
    (
        "도우미를 시작하지 못했습니다(오류 {}).",
        "Could not start the helper (error {}).",
    ),
    (
        "도우미가 시작하자마자 끝났습니다. '로그 보기'로 이유를 확인하세요.",
        "The helper ended right after it started. See why with 'View log'.",
    ),
    (
        "goyo-sync.conf를 저장하지 못했습니다. 이 폴더에 쓸 수 있는지 확인하세요.",
        "Could not save goyo-sync.conf. Check that this folder is writable.",
    ),
    (
        "자동 시작 설정을 바꾸지 못했습니다(오류 {}).",
        "Could not change the autostart setting (error {}).",
    ),
    (
        "지금 동기화를 마쳤습니다: 정상 {}개, 문제 {}개. 금고마다 결과가 목록에 보입니다.",
        "Sync finished: {} OK, {} with problems. Each vault's result is shown in the list.",
    ),
    (
        "실행 중인 도우미에 중지 신호를 보냈습니다.",
        "The running helper was asked to stop.",
    ),
    ("실행 중인 도우미가 없습니다.", "No helper is running."),
    (
        "금고를 추가했습니다. '저장하고 시작'을 누르면 적용됩니다.",
        "Vault added. 'Save and start' applies it.",
    ),
    (
        "목록에서 뺐습니다. '저장하고 시작'을 누르면 적용됩니다. 금고 옆 동기화 폴더는 그대로 남습니다.",
        "Removed from the list. 'Save and start' applies it. The sync folder next to the vault stays.",
    ),
    (
        "고요 금고 파일(.goyo·.goyokey)은 전용 키로 쓸 수 없습니다. SSH 개인 키를 고르세요.",
        "A Goyo Vault file (.goyo or .goyokey) cannot be the dedicated key. Choose an SSH private key.",
    ),
    (
        "뺄 금고를 목록에서 고르세요.",
        "Choose the vault to remove in the list.",
    ),
    ("서버", "Server"),
    ("스크립트 경로", "Script path"),
    ("전용 키 파일", "Dedicated key file"),
    ("간격", "Interval"),
    ("제한 시간", "Timeout"),
    ("금고 경로", "Vault path"),
    (
        "{}에 #를 쓸 수 없습니다. goyo-sync.conf에서 주석을 시작하는 기호입니다.",
        "{} cannot contain #: it starts a comment in goyo-sync.conf.",
    ),
    (
        "설정이 8 KiB를 넘습니다. 금고 경로가 너무 깁니다.",
        "The settings would exceed 8 KiB: the vault paths are too long.",
    ),
    (
        "서버(ssh 호스트)를 적으세요.",
        "Enter the server (ssh host).",
    ),
    (
        "서버는 ssh 별칭이나 호스트 이름이어야 합니다(영문·숫자·. _ -, user@ 허용, -로 시작 불가).",
        "The server must be an ssh alias or host name (letters, digits, . _ -, optional user@, not starting with -).",
    ),
    (
        "서버의 스크립트 경로는 영문·숫자·. _ / ~ + -만 쓸 수 있고 -로 시작할 수 없습니다.",
        "The script path may use only letters, digits and . _ / ~ + -, and cannot start with -.",
    ),
    (
        "파이썬 명령은 영문·숫자·. _ / + -만 쓸 수 있고 -로 시작할 수 없습니다.",
        "The Python command may use only letters, digits and . _ / + -, and cannot start with -.",
    ),
    (
        "전용 키 파일은 있는 SSH 개인 키 파일의 절대 경로여야 합니다(.goyo·.goyokey 불가).",
        "The dedicated key must be the full path of an existing SSH private key file (not .goyo or .goyokey).",
    ),
    (
        "간격은 30~3600초 사이의 숫자여야 합니다.",
        "The interval must be a number from 30 to 3600 seconds.",
    ),
    (
        "제한 시간은 30~600초 사이의 숫자여야 합니다.",
        "The timeout must be a number from 30 to 600 seconds.",
    ),
    (
        "열쇠 파일(.goyokey)은 동기화하지 않습니다. 금고 파일(.goyo)을 고르세요.",
        "Key files (.goyokey) are never synced. Choose a vault file (.goyo).",
    ),
    (
        "이미 목록에 있는 금고입니다.",
        "This vault is already in the list.",
    ),
    (
        "금고는 8개까지 넣을 수 있습니다.",
        "The list holds at most 8 vaults.",
    ),
    (
        "동기화할 금고를 하나 이상 추가하세요.",
        "Add at least one vault to sync.",
    ),
    (
        "이 금고 경로는 쓸 수 없습니다(절대 경로만, 따옴표·와일드카드·장치 경로 불가): {}",
        "This vault path cannot be used (full paths only; no quotes, wildcards or device paths): {}",
    ),
    (
        "서버에 동기화 스크립트가 없습니다({}). '서버에 설치·업데이트'로 설치하세요.",
        "The sync script is not on the server ({}). Install it with 'Install or update on server'.",
    ),
    (
        "서버에 연결할 수 없습니다. 네트워크·VPN과 서버 이름을 확인하세요.",
        "Cannot reach the server. Check the network, the VPN and the server name.",
    ),
    (
        "SSH 인증에 실패했습니다. 키나 ssh-agent, 서버의 authorized_keys를 확인하세요. 암호를 묻는 키는 쓸 수 없습니다.",
        "SSH authentication failed. Check the key or ssh-agent and the server's authorized_keys. A key that asks for a passphrase cannot be used.",
    ),
    (
        "서버 호스트 키를 확인해야 합니다. '연결 확인'을 누르세요.",
        "The server's host key needs checking. Press 'Check connection'.",
    ),
    (
        "Windows OpenSSH 클라이언트(ssh.exe)가 없습니다. 설정 > 시스템 > 선택적 기능에서 'OpenSSH 클라이언트'를 추가하세요.",
        "The Windows OpenSSH client (ssh.exe) is missing. Add 'OpenSSH Client' under Settings > System > Optional features.",
    ),
    (
        "서버가 요청을 거부했습니다. goyo-sync.log를 확인하세요.",
        "The server refused the request. See goyo-sync.log.",
    ),
    (
        "서버 사본이 더 새로운 형식입니다. 고요 금고와 goyo-sync를 업데이트하세요.",
        "The server copy uses a newer format. Update Goyo Vault and goyo-sync.",
    ),
    ("설정을 확인하세요.", "Check the settings."),
    (
        "서버 또는 통신 오류입니다. 서버 스크립트와 파이썬을 확인하고 goyo-sync.log를 보세요.",
        "Server or protocol error. Check the server script and Python, and see goyo-sync.log.",
    ),
    (
        "서버 또는 통신 오류입니다(ssh: {}). 서버 스크립트와 파이썬을 확인하세요.",
        "Server or protocol error (ssh: {}). Check the server script and Python.",
    ),
    (
        "known_hosts에 저장된 {} 서버의 호스트 키:\n\n{}\n\n서버에서 직접 확인한 지문과 같은지 비교하세요. 서버에서는 예를 들어 ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub 로 볼 수 있습니다. 다르면 ssh-keygen -R {} 으로 지우고 이 서버에 연결하지 마세요.",
        "Host key of {} now in known_hosts:\n\n{}\n\nCompare it with the fingerprint you check on the server itself, for example with ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub there. If they differ, remove it with ssh-keygen -R {} and do not use this server.",
    ),
    (
        "호스트 키를 저장했는지 확인하지 못했습니다. PowerShell에서 ssh-keygen -l -F {} 로 지문을 보고 서버의 지문과 비교하세요.",
        "Could not confirm the stored host key. Run ssh-keygen -l -F {} in PowerShell and compare the fingerprint with the server's.",
    ),
    (
        "{} 서버에 동기화 스크립트를 설치하거나 업데이트합니다.\n\n서버 경로: {} (/로 시작하지 않으면 홈 폴더 기준)\n확인: 보낸 스크립트를 먼저 {} -I로 selftest하고, PASS일 때만 기존 스크립트와 바꿉니다.\n\n설치에는 평소의 ssh 로그인(기본 키나 ssh-agent)을 쓰고, '전용 키 파일'은 쓰지 않습니다. 전용 키는 서버에서 동기화 명령만 실행하도록 묶여 있을 수 있기 때문입니다. 계속할까요?",
        "This installs or updates the sync script on {}.\n\nPath on the server: {} (from your home folder unless it starts with /)\nCheck: the new copy first runs its selftest with {} -I and replaces the old script only if it prints PASS.\n\nThe install uses your usual ssh login (default key or ssh-agent), not the dedicated key file, because that key may be bound on the server to run only the sync command. Continue?",
    ),
    (
        "이 PC는 아직 {} 서버의 호스트 키를 모릅니다(처음 연결).\n\n'예'를 누르면 이번 한 번만 서버가 보내는 키를 확인 없이 믿고 known_hosts에 저장합니다(처음 사용할 때 신뢰). 지금 누군가 연결을 가로채고 있다면 그 사람의 키가 저장됩니다. 그 뒤로는 키가 바뀌면 연결하지 않습니다.\n\n저장한 뒤 지문을 보여 드리니, 서버에서 직접 본 지문과 꼭 비교하세요. 이 키를 믿고 저장할까요?",
        "This PC does not know the host key of {} yet (first connection).\n\n'Yes' trusts the key the server sends, this once and without checking, and stores it in known_hosts (trust on first use). If someone is intercepting the connection right now, their key is stored. From then on a changed key is refused.\n\nThe fingerprint is shown once it is stored; be sure to compare it with the one you see on the server itself. Trust and store this key?",
    ),
    (
        "금고 파일을 찾을 수 없습니다. 경로를 확인하세요.",
        "Vault file not found. Check the path.",
    ),
    (
        "아직 설정 전 · '저장하고 시작'하면 금고 옆에 동기화 폴더를 만듭니다",
        "Not set up yet · 'Save and start' makes the sync folder next to the vault",
    ),
    (
        "동기화 폴더가 링크이거나 폴더가 아니어서 쓰지 않습니다",
        "The sync folder is a link or not a folder, so it is not used",
    ),
    (
        "도우미 꺼짐 · 마지막 서버 버전 {}",
        "Helper off · last server version {}",
    ),
    ("정상 · 서버 버전 {}", "OK · server version {}"),
    (
        "정상 · 서버에 아직 사본 없음",
        "OK · no copy on the server yet",
    ),
    (
        "고요 금고에서 동기화 동의를 기다리는 중 · 금고를 열면 묻습니다",
        "Waiting for consent in Goyo Vault · it asks when you unlock the vault",
    ),
    (
        "오프라인 · 변경은 이 PC에 남아 있다가 연결되면 올라갑니다",
        "Offline · changes stay on this PC and go up once connected",
    ),
    (
        "SSH 인증 실패 · '연결 확인'으로 확인하세요",
        "SSH authentication failed · see 'Check connection'",
    ),
    (
        "호스트 키 확인 필요 · '연결 확인'을 누르세요",
        "Host key needs checking · press 'Check connection'",
    ),
    ("ssh.exe가 없습니다", "ssh.exe is missing"),
    (
        "서버 오류 · '로그 보기'로 확인하세요",
        "Server error · see 'View log'",
    ),
    (
        "업로드 거부됨 · '로그 보기'로 확인하세요",
        "Upload refused · see 'View log'",
    ),
    (
        "설정 오류 · 설정을 고친 뒤 저장하세요",
        "Settings error · fix the settings and save",
    ),
    (
        "새 형식 · 고요 금고를 업데이트하세요",
        "Newer format · update Goyo Vault",
    ),
    ("서버 스크립트 업데이트 필요", "Server script update needed"),
    ("열쇠 파일 갱신 필요", "Key file update needed"),
    (
        "실행 중인 도우미가 처리하고 있어 건너뛰었습니다",
        "Skipped: the running helper is working on it",
    ),
    (
        "지금 동기화: 올렸습니다 · 서버 버전 {}",
        "Synced now: uploaded · server version {}",
    ),
    (
        "지금 동기화: 새 서버 버전 {}을 받았습니다",
        "Synced now: received server version {}",
    ),
    (
        "지금 동기화: 최신입니다 · 서버 버전 {}",
        "Synced now: up to date · server version {}",
    ),
    (
        "지금 동기화: 서버에 아직 사본이 없습니다",
        "Synced now: the server has no copy yet",
    ),
    ("이 PC의 {}와 같은 금고", "Same vault as {} on this PC"),
    ("금고 ID {}", "Vault ID {}"),
    ("{} · 버전 {}", "{} · version {}"),
    ("{} KB · {} UTC 저장", "{} KB · stored {} UTC"),
    (
        "저장하지 않은 변경이 있습니다. 저장하지 않고 닫을까요?",
        "There are unsaved changes. Close without saving?",
    ),
    (
        "화면을 만들 수 없어 종료합니다.",
        "The window could not be created, so goyo-sync stops.",
    ),
    (
        "로그인할 때 자동으로 시작하지 않습니다. 지금 실행 중인 도우미는 '중지'로 멈추세요.",
        "It no longer starts when you sign in. Stop the helper running now with 'Stop'.",
    ),
    (
        "로그인할 때 자동으로 시작하지 않습니다.",
        "It no longer starts when you sign in.",
    ),
    (
        "열쇠는 바꾸지 않았습니다. 지금까지 쓰던 비밀번호로 다시 여세요.",
        "The key was not changed. Open the vault again with the password you have used so far.",
    ),
    (
        "열쇠 변경은 저장되었습니다. 다음에 열 때는 바뀐 열쇠 파일의 비밀번호로 여세요(비밀번호를 바꿨다면 새 비밀번호입니다). 연 뒤 '열쇠 백업'을 하세요.",
        "The key change was saved. Next time, open the vault with the changed key file's password (the new one, if you changed the password). After opening, use 'Back up key'.",
    ),
    (
        "열쇠 백업을 다시 읽어 확인하지 못했습니다. 다른 저장장치에 다시 백업하세요.",
        "The key backup could not be read back and checked. Back up again to another drive.",
    ),
    (
        "이 금고 파일은 이 PC가 마지막으로 쓴 열쇠가 아닌 예전 열쇠로 저장되어 있어 열지 않았습니다. 예전 열쇠 사본을 가진 누군가가 금고 파일을 바꿔 넣었을 수 있습니다. 예전 백업을 되살리려는 것이라면 '백업 파일로 되살리기'로 새 파일에 복원하세요. 그런 일이 없었다면 이 금고 파일을 최근 백업이나 서버 기록과 비교하세요.",
        "This vault file is saved under an older key, not the key this PC used last, so it was not opened. Someone with an old copy of the key may have swapped the vault file. To bring back an old backup, restore it to a new file with 'Restore from a backup file'. If nothing like that happened, compare this vault file with a recent backup or the server history.",
    ),
    (
        "이 금고 파일은 예전 열쇠로 저장되어 있고 저장 횟수 기록이 비정상적으로 커서 열지 않았습니다. 손상되었거나 예전 열쇠 사본을 가진 누군가가 만든 파일일 수 있습니다. 비밀번호가 틀린 것이 아닙니다. 다른 백업이나 서버 기록을 확인하세요.",
        "This vault file is saved under an older key and its save counters are abnormally large, so it was not opened. It may be damaged, or made by someone with an old copy of the key. Your password is not wrong. Check another backup or the server history.",
    ),
    (
        "지난 열쇠 변경이 끝나지 않아 예전 열쇠로 열었습니다. 다시 바꾸려면 '열쇠 관리'를 쓰세요.",
        "The last key change did not finish, so the vault opened with the old key. To change it again, use 'Key management'.",
    ),
    (
        "열쇠 변경이 중간에 끊긴 흔적이 있습니다. 예전 비밀번호(와 보안 키)로 열어 보세요.",
        "A key change was cut off midway. Try opening with the old password (and security key).",
    ),
    (
        "이 PC에서 한 열쇠 변경은 저장되었습니다. 새로 정한 비밀번호로 여세요.",
        "The key change made on this PC was saved. Open the vault with the password you just set.",
    ),
    (
        "이 PC에서 받은 열쇠 파일은 저장되었습니다. 그 열쇠 파일의 비밀번호(다른 PC에서 정한 비밀번호)로 여세요.",
        "The key file this PC received was saved. Open the vault with that key file's password (the one set on the other PC).",
    ),
    (
        "이 PC에서 한 열쇠 변경 뒤에 다른 PC가 이 열쇠 파일을 다시 바꿨습니다. 그 PC에서 정한 비밀번호로 여세요.",
        "After this PC's key change, another PC changed this key file again. Open the vault with the password set on that PC.",
    ),
    (
        "열쇠 변경이 거의 끝난 상태로 열쇠 파일이 임시 파일로 남았습니다. 새 비밀번호(와 보안 키)로 여세요. 예전 비밀번호로 열려면 예전 열쇠 파일 백업이 필요합니다.",
        "A key change almost finished, and the key file was left as a temporary file. Open the vault with the new password (and security key). Opening it with the old password needs a backup of the old key file.",
    ),
    (
        "이 열쇠 파일은 이 고요 금고가 전에 본 것(수정 {old})보다 오래되었습니다(수정 {new}). 직접 예전 백업으로 되돌렸거나, 같은 고요 금고 폴더를 다른 PC와 함께 쓰는데 그 PC에서 바꾼 새 열쇠 파일을 아직 받지 않은 경우라면 정상입니다(뒤의 경우 '새 열쇠 파일 받기'를 하세요). 그런 일이 없었다면 누군가 예전 열쇠 파일과 금고 파일로 바꿔 놓았을 수 있으니 백업을 확인하세요.",
        "This key file is older than the one this Goyo Vault saw before (revision {old}; this one is revision {new}). That is normal if you went back to an old backup yourself, or if you share this Goyo Vault folder with another PC and have not received the new key file changed there yet (then use 'Receive a new key file'). If nothing like that happened, someone may have put back an old key file and vault file: check your backups.",
    ),
    (
        "이 PC가 마지막으로 본 열쇠 파일(수정 {old})과 다른 열쇠 파일(수정 {new})로 복원했습니다. 복원한 금고에서는 열쇠를 바꾸거나 새 열쇠 파일을 받거나 서버에 올리거나 서버 사본을 합치지 않습니다. 필요한 항목을 확인하는 데 쓰세요.",
        "Restored with a key file other than the one this PC saw last (revision {old}): this one is revision {new}. The restored vault changes no key, receives no key file, uploads nothing and merges no server copy. Use it to look up the entries you need.",
    ),
    (
        "복원한 금고에서는 열쇠를 바꾸거나 새 열쇠 파일을 받지 않습니다. 바꾸면 같은 열쇠 파일을 쓰는 다른 금고 파일은 '복원'으로만 열립니다. 복원한 파일을 계속 쓰려면 잠근 뒤 로그인으로 여세요.",
        "A restored vault does not change its key or receive a new key file: other vault files that use the same key file would then open only through Restore. To keep using the restored file, lock it and open it by logging in.",
    ),
    (
        "이 PC의 열쇠 기록(goyo-vault.keys)을 처음에 읽지 못했거나 여는 동안 바뀌어 열지 않았습니다. 다시 여세요.",
        "This PC's key record (goyo-vault.keys) could not be read at first, or changed while the vault was opening, so it was not opened. Open it again.",
    ),
    (
        "이 PC에서 하던 열쇠 변경이 아직 끝나지 않았습니다. 원래 금고 파일을 그 열쇠 파일로 다시 열면 마저 끝납니다. 그때까지 복원한 금고에서는 열쇠를 바꾸거나 새 열쇠 파일을 받거나 서버에 올리거나 서버 사본을 합치지 않습니다. 필요한 항목을 확인하는 데 쓰세요.",
        "A key change on this PC has not finished yet. Opening the original vault file with that key file finishes it. Until then the restored vault changes no key, receives no key file, uploads nothing and merges no server copy. Use it to look up the entries you need.",
    ),
    (
        "이 PC에서 하던 열쇠 변경이 다른 열쇠 파일({path})에 저장되었을 수 있는데, 그 파일을 읽지 못했습니다. 그 파일로 열면 마저 끝나며, 그때까지 열쇠를 바꾸거나 새 열쇠 파일을 받지 않습니다. 그 파일을 잃어버렸거나 쓸 수 없다면, 또는 지금 연 파일이 드라이브 문자만 바뀐 그 파일이라면 '열쇠 관리'에서 [끝나지 않은 열쇠 변경 버리기…]를 누르세요.",
        "A key change on this PC may have been saved in another key file ({path}), which could not be read. Opening the vault with that file finishes it; until then this PC changes no key and receives no key file. If that file is lost or unusable, or is the file you opened under a new drive letter, press [Discard the unfinished key change…] in 'Key management'.",
    ),
    (
        "이 PC에서 하던 열쇠 변경이 {path}에 저장되었는지 확인하지 않고 그 기록을 버립니다. 그 열쇠 파일을 잃어버렸거나 더 쓸 수 없을 때만 계속하세요. 나중에 그 파일을 다시 찾으면 이 PC의 것으로 알아보지 못하고 다른 열쇠 파일처럼 다룹니다(갈라졌다면 '새 열쇠 파일 받기'로 합치세요). 계속할까요?",
        "This discards the record of this PC's key change without checking whether it was saved in {path}. Continue only if that key file is lost or can no longer be used. If you find the file again later, this PC will not recognize it as its own and treats it like any other key file (if they diverged, join them with 'Receive a new key file'). Continue?",
    ),
    (
        "끝나지 않은 열쇠 변경 기록을 버렸습니다. 이제 이 PC에서 열쇠를 바꾸거나 새 열쇠 파일을 받을 수 있습니다.",
        "The record of the unfinished key change was discarded. This PC can now change keys and receive key files again.",
    ),
    (
        "이 열쇠 파일은 아직 '열쇠 백업'으로 백업하지 않았습니다. 열쇠 파일을 잃으면 비밀번호가 있어도 열 수 없습니다.",
        "This key file has not been backed up with 'Back up key' yet. If you lose the key file, the vault cannot be opened even with the password.",
    ),
    (
        "이 PC가 마지막으로 본 열쇠 파일(수정 {old}) 대신 지금 열쇠 파일(수정 {new})을 이 금고의 열쇠 파일로 정합니다. 직접 예전 열쇠 파일로 되돌린 것이 맞을 때만 계속하세요. 그 뒤로 이 PC는 수정 {new}보다 나중의 열쇠 변경을 기억하지 않습니다. 계속할까요?",
        "In place of the key file this PC saw last (revision {old}), this makes the current key file (revision {new}) this vault's key file. Continue only if you went back to the old key file yourself. Afterwards this PC no longer remembers key changes later than revision {new}. Continue?",
    ),
    (
        "이 PC가 마지막으로 본 열쇠 파일(수정 {old}) 대신 지금 열쇠 파일(수정 {new})을 이 금고의 열쇠 파일로 정합니다. 직접 예전 열쇠 파일로 되돌린 것이 맞을 때만 계속하세요. 그 뒤로 이 PC는 수정 {new}보다 나중의 열쇠 변경을 기억하지 않습니다.\n서버 사본이 더 나중의 열쇠로 저장되어 있으면 그 뒤 동기화가 멈춥니다. 그 사본을 이 PC가 올렸다면 '열쇠 관리'에서 [서버 사본을 이 PC 상태로 덮어쓰기…]를 누르세요.\n계속할까요?",
        "In place of the key file this PC saw last (revision {old}), this makes the current key file (revision {new}) this vault's key file. Continue only if you went back to the old key file yourself. Afterwards this PC no longer remembers key changes later than revision {new}.\nIf the server copy was saved under a later key, sync then stops. If this PC uploaded that copy, press [Overwrite the server copy with this PC's state…] under 'Key management'.\nContinue?",
    ),
    (
        "이 PC에서 이 금고는 보안 키 열쇠 파일로 열었습니다. 비밀번호만으로 여는 열쇠 파일로는 열지 않습니다. 다른 PC에서 보안 키를 끈 것이 맞다면, 보안 키를 지원하는 고요 금고에서 원래 열쇠 파일로 연 뒤 '새 열쇠 파일 받기'로 받으세요.",
        "On this PC this vault was opened with a security-key key file. It is not opened with a key file that needs only the password. If security keys were really turned off on another PC, open the vault with the original key file in a Goyo Vault with security-key support, then take the new file with 'Receive a new key file'.",
    ),
    (
        "이 열쇠 파일에는 이 PC가 기록해 둔 키 제거 기록이 빠져 있습니다. 예전 열쇠 파일로 되돌려졌거나 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요. 다른 PC의 열쇠 파일이라면 이 PC의 원래 열쇠 파일로 연 뒤 '새 열쇠 파일 받기'로 받으세요.",
        "This key file lacks a key removal this PC recorded. It may have been put back to an old key file or forged, so it was not opened. Use the latest key file (a key backup, another PC). If it is another PC's key file, open the vault with this PC's original key file, then take it with 'Receive a new key file'.",
    ),
    (
        "이 열쇠 파일이 맞는 것이 확실하고 다른 방법이 없으면, 마지막 방법으로 고요 금고를 모두 닫고 %LOCALAPPDATA%\\GoyoVault 폴더의 goyo-vault.keys와 goyo-vault.keys.로 시작하는 .tmp 파일을 지운 뒤 다시 여세요. 이 PC에 있는 모든 금고의 열쇠 기록이 함께 지워집니다(README의 '이 PC의 열쇠 기록'을 보세요).",
        "If you are sure this key file is right and nothing else works, as a last resort close every Goyo Vault, delete goyo-vault.keys and the .tmp files starting with goyo-vault.keys. in the %LOCALAPPDATA%\\GoyoVault folder, and open the vault again. This deletes the key records of every vault on this PC (see 'This PC's key record' in the README).",
    ),
    (
        "이 열쇠 파일의 수정 번호(수정 {new})가 이 PC가 본 것(수정 {old})보다 비정상적으로 큽니다. 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요.",
        "This key file's revision (revision {new}) is abnormally far above the one this PC saw (revision {old}). It may be forged, so it was not opened. Use the latest key file (a key backup, another PC).",
    ),
    (
        "이 PC의 열쇠 기록(goyo-vault.keys)은 더 새로운 고요 금고가 쓴 것이라 이 버전은 고치지 않습니다. 이번 세션 동안만 기억합니다. 더 새로운 고요 금고를 쓰세요.",
        "This PC's key record (goyo-vault.keys) was written by a newer Goyo Vault, so this version does not change it and remembers this session only. Use the newer Goyo Vault.",
    ),
    (
        "이 PC의 열쇠 상태 기록(goyo-vault.keys)을 저장하지 못했습니다. 이번 세션 동안만 기억합니다. 잠근 뒤에는 이 PC가 예전 열쇠 파일로 되돌려진 것을 알아채지 못하거나, 끊긴 열쇠 변경을 이 PC의 것으로 알아보지 못할 수 있습니다. %LOCALAPPDATA%\\GoyoVault 폴더의 쓰기 권한을 확인하세요.",
        "This PC's key state record (goyo-vault.keys) could not be saved, so it is remembered for this session only. After locking, this PC may not notice that an old key file was put back, or may not recognize a cut-off key change as its own. Check the write permission of the %LOCALAPPDATA%\\GoyoVault folder.",
    ),
    (
        "새 비밀번호가 지금 비밀번호와 같습니다.",
        "The new password is the same as the current one.",
    ),
    (
        "열쇠를 바꿨습니다. 금고 파일을 아직 새 열쇠로 다시 저장하지 못했습니다. 저장장치를 확인하세요. 다음 저장이나 잠금 해제 때 자동으로 마칩니다.",
        "The key was changed. The vault file could not be saved under the new key yet. Check the drive. The next save or unlock finishes it automatically.",
    ),
    (
        "열쇠 파일 이름 바꾸기가 끊겨 임시 파일로 두었습니다. 자동으로 다시 시도합니다.",
        "Renaming the key file was cut off, so it was kept as a temporary file. It is tried again automatically.",
    ),
    (
        "열쇠 파일과 그 임시 파일을 모두 찾지 못했습니다. 잠그기 전에 '열쇠 백업'으로 새 열쇠 파일을 저장하세요. 그 파일과 새 비밀번호로 이 금고를 열 수 있습니다.",
        "Neither the key file nor its temporary file can be found. Before locking, save the new key file with 'Back up key'. That file and the new password open this vault.",
    ),
    (
        "열쇠 파일을 저장하지 못했습니다(저장장치·쓰기 권한 확인). 아무것도 바뀌지 않았습니다.",
        "The key file could not be saved (check the drive and write permission). Nothing was changed.",
    ),
    (
        "열쇠 파일을 저장했는지 확인하지 못했습니다. 잠그기 전에 새 열쇠 파일을 다른 저장장치에 저장하세요. 그 파일과 새 비밀번호(와 보안 키)로 이 금고를 열 수 있습니다.",
        "It could not be confirmed that the key file was saved. Before locking, save the new key file to another drive ('Back up key'). That file and the new password (and security key) open this vault.",
    ),
    (
        "열쇠 파일을 저장했는지 확인하지 못해 금고를 잠갔습니다. 먼저 새 비밀번호(와 보안 키)로 열어 보세요. 열리지 않으면 예전 비밀번호로 여세요. 예전 열쇠 파일이 없어졌다면 열쇠 백업이 필요합니다.",
        "It could not be confirmed that the key file was saved, so the vault was locked. First try opening it with the new password (and security key). If that fails, open it with the old password. If the old key file is gone, you need a key backup.",
    ),
    (
        "확인한 지 오래되었거나 다른 화면에서 확인한 것이라 다시 확인해야 합니다. 처음부터 다시 하세요.",
        "The confirmation is too old or came from another screen, so it must be done again. Start over.",
    ),
    (
        "새 열쇠 파일이나 금고 파일을 검증하지 못해 쓰지 않았습니다. 아무것도 바뀌지 않았습니다.",
        "The new key file or vault file did not pass verification, so it was not written. Nothing was changed.",
    ),
    (
        "다른 PC나 백업에 이 PC보다 새 열쇠 파일이 있습니다(보안 키 추가 등). 먼저 '새 열쇠 파일 받기'로 그 파일을 받으세요. 이대로 바꾸면 두 열쇠 파일이 갈라집니다(나중에 받으면 합쳐집니다). 그래도 계속할까요?",
        "Another PC or a backup has a newer key file than this PC (a security key added, for example). First take that file with 'Receive a new key file'. Changing the key now splits the two key files (taking it later joins them). Continue anyway?",
    ),
    (
        "이 PC가 서버와 맞춰졌는지 확인되지 않았습니다. 다른 PC에서도 따로 열쇠를 바꾸면 두 열쇠가 갈라져 '새 열쇠 파일 받기'로 합쳐야 합니다. 계속할까요?",
        "It is not confirmed that this PC is up to date with the server. If another PC also changes the key on its own, the two keys split and must be joined with 'Receive a new key file'. Continue?",
    ),
    (
        "확인하거나 버릴 열쇠 기록이 없습니다.",
        "There is no key record to confirm or discard.",
    ),
    ("QR 데이터가 너무 깁니다.", "The QR data is too long."),
    (
        "이 열쇠 파일은 이 PC가 마지막으로 본 열쇠 파일에서 이어진 새 버전이 아니라, 그와 갈라진 다른 열쇠 파일입니다(다른 PC에서 따로 열쇠를 바꿨거나, 누군가 예전 열쇠 파일로 새로 만들었을 수 있습니다). 그대로 쓰면 이 PC의 열쇠 변경이 사라지므로 열지 않았습니다.",
        "This key file is not a later version of the key file this PC saw last, but another key file that split from it (another PC changed the key on its own, or someone made it from an old key file). Using it would lose this PC's key changes, so it was not opened.",
    ),
    (
        "다른 PC에서 바꾼 것이 맞다면 이 PC의 원래 열쇠 파일(열쇠 백업)로 연 뒤 '새 열쇠 파일 받기'로 이 파일을 받으면 두 파일이 합쳐집니다. 그런 변경을 한 PC가 없다면 받지 말고 백업을 확인하세요.",
        "If another PC really changed it, open the vault with this PC's original key file (a key backup), then take this file with 'Receive a new key file': the two files are joined. If no PC made such a change, do not take it, and check your backups.",
    ),
    (
        "금고 파일도 이 열쇠 파일의 열쇠로 저장되어 있어 이 PC의 원래 열쇠 파일로는 열리지 않습니다. 이 PC의 금고 백업이 있으면 원래 열쇠 파일과 그 백업으로 연 뒤 '새 열쇠 파일 받기'로 이 열쇠 파일을 받고, 이 금고 파일은 그 뒤 '백업 파일로 되살리기'로 새 파일에 되살려 항목을 확인하세요.",
        "The vault file is saved under this key file's key too, so this PC's original key file cannot open it. If you have a vault backup of this PC, open it with the original key file, take this key file with 'Receive a new key file', and afterwards restore this vault file to a new file with 'Restore from a backup file' to check its entries.",
    ),
    (
        "이 금고 파일의 항목만 확인하려면 지금 이 열쇠 파일로 '복원'하세요(복원한 금고에서는 열쇠를 바꾸거나 올리지 않습니다).",
        "To only look at this vault file's entries, restore it now with this key file (a restored vault changes no key and uploads nothing).",
    ),
    (
        "이 금고 파일은 다른 PC에서 바꾼 새 열쇠 파일(수정 {V.epoch})로 저장되어 있어 이 열쇠 파일(수정 {K.epoch})로는 열리지 않습니다.",
        "This vault file is saved with a new key file changed on another PC (revision {V.epoch}), so this key file (revision {K.epoch}) cannot open it.",
    ),
    (
        "금고 파일을 여러 PC가 함께 쓰고 열쇠 파일은 PC마다 따로 두었다면, 열쇠를 바꾼 PC의 새 열쇠 파일을 USB로 가져와 그 파일로 여세요. 이 PC에서 따로 열쇠를 바꾼 적이 없다면 그 파일을 이 PC의 열쇠 파일 자리에 두어도 됩니다. 그 새 열쇠 파일이 어디에도 없다면 열쇠를 바꾼 PC의 열쇠 백업이 필요합니다.",
        "If several PCs share the vault file and each keeps its own key file, bring the new key file of the PC that changed the key by USB and open the vault with it. If this PC never changed the key on its own, that file may take this PC's key file's place. If that new key file is nowhere, you need the key backup of the PC that changed the key.",
    ),
    (
        "이 금고 파일은 다른 PC에서 바꾼 새 열쇠 파일(수정 {V.epoch})로 저장되어 있어 이 열쇠 파일(수정 {K.epoch})로는 열리지 않습니다.\r\n금고 파일을 여러 PC가 함께 쓰고 열쇠 파일은 PC마다 따로 두었다면, 열쇠를 바꾼 PC의 새 열쇠 파일을 USB로 가져와 그 파일로 여세요. 이 PC에서 따로 열쇠를 바꾼 적이 없다면 그 파일을 이 PC의 열쇠 파일 자리에 두어도 됩니다. 그 새 열쇠 파일이 어디에도 없다면 열쇠를 바꾼 PC의 열쇠 백업이 필요합니다.",
        "This vault file is saved with a new key file changed on another PC (revision {V.epoch}), so this key file (revision {K.epoch}) cannot open it.\r\nIf several PCs share the vault file and each keeps its own key file, bring the new key file of the PC that changed the key by USB and open the vault with it. If this PC never changed the key on its own, that file may take this PC's key file's place. If that new key file is nowhere, you need the key backup of the PC that changed the key.",
    ),
    (
        "이미 같은 열쇠 파일입니다.",
        "It is the same key file already.",
    ),
    (
        "이 열쇠 파일은 이 PC의 열쇠 파일보다 오래되었습니다.",
        "This key file is older than this PC's key file.",
    ),
    (
        "이 PC의 열쇠 파일에 이미 모두 들어 있습니다.",
        "This PC's key file already holds everything in it.",
    ),
    (
        "이 열쇠 파일은 이 금고의 것이 아닙니다.",
        "This key file does not belong to this vault.",
    ),
    (
        "이 열쇠 파일은 받지 않았습니다({reason}). 이 PC의 열쇠 파일과 맞지 않는 변경이 들어 있어 손상되었거나 위조되었을 수 있습니다. 다른 PC에서 바꾼 것이 맞다면 그 PC의 최신 열쇠 파일을 다시 가져오세요.",
        "This key file was not taken ({reason}). It holds changes that do not fit this PC's key file, so it may be damaged or forged. If another PC really changed it, bring that PC's latest key file again.",
    ),
    ("수정 번호가 너무 큼", "revision number too large"),
    ("제거 기록이 빠짐", "a key removal is missing"),
    (
        "이 PC는 지금 이 PC가 전에 쓴 것(수정 {old})보다 오래된 열쇠 파일로 열려 있어, 그 최신 열쇠 파일에서 이어지지 않은 열쇠 파일은 받지 않았습니다. 이 PC가 전에 쓴 최신 열쇠 파일(열쇠 백업)로 다시 연 뒤 받으세요. 지금 열쇠 파일이 맞다면 먼저 '열쇠 관리'에서 [이 열쇠 파일이 맞습니다]를 누르세요.",
        "This PC is open with a key file older than the one it wrote before (revision {old}), so a key file that does not follow from that latest key file was not taken. Open the vault again with the latest key file this PC wrote (a key backup), then take it. If the current key file is right, first press [This key file is right] in 'Key management'.",
    ),
    (
        "받을 열쇠 파일을 확인한 뒤에 이 PC의 열쇠 파일이나 그 파일이 바뀌었습니다. 처음부터 다시 하세요.",
        "This PC's key file or the key file to take changed after it was checked. Start over.",
    ),
    (
        "다른 PC에서 이 금고의 열쇠를 바꿔 동기화를 멈췄습니다. 그 PC의 새 열쇠 파일을 USB로 가져와 '열쇠 관리 › 새 열쇠 파일 받기'로 받으세요. 이 PC의 열쇠 파일에 덮어쓰지는 마세요. 그때까지 이 PC의 변경은 이 PC에만 저장됩니다.",
        "Another PC changed this vault's key, so sync stopped. Bring that PC's new key file by USB and take it with 'Key management › Receive a new key file'. Do not copy it over this PC's key file. Until then, this PC's changes are saved on this PC only.",
    ),
    (
        "어느 PC에서도 열쇠를 바꾸지 않았다면 서버 사본이 위조되었을 수 있습니다. 열쇠를 바꾼 PC를 더 쓸 수 없다면 '열쇠 관리'에서 서버 사본을 이 PC 상태로 덮어쓸 수 있습니다.",
        "If no PC changed the key, the server copy may be forged. If the PC that changed the key can no longer be used, you can overwrite the server copy with this PC's state in 'Key management'.",
    ),
    (
        "다른 PC에서 이 금고에 보안 키를 켜서 동기화를 멈췄습니다. 이 고요 금고 빌드는 보안 키를 지원하지 않아 그 열쇠 파일을 받을 수 없습니다(docs/SECURITY_KEY.md).",
        "Another PC turned on security keys for this vault, so sync stopped. This Goyo Vault build does not support security keys and cannot take that key file (docs/SECURITY_KEY.md).",
    ),
    (
        "이 PC의 변경은 이 PC에만 저장됩니다. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.",
        "This PC's changes are saved on this PC only. If nothing like that happened, the server copy may be forged.",
    ),
    (
        "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라졌습니다. 동기화를 멈췄습니다. 한 PC에서 '열쇠 관리 › 새 열쇠 파일 받기'로 다른 PC의 열쇠 파일을 받으면 두 열쇠 파일을 합칩니다. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.",
        "Two PCs changed the key separately, so the key files diverged. Sync stopped. On one PC, take the other PC's key file with 'Key management › Receive a new key file' to join the two key files. If nothing like that happened, the server copy may be forged.",
    ),
    (
        "서버 사본이 이 PC의 예전 열쇠 이름을 달고 있지만 열리지 않아 동기화를 멈췄습니다. 손상되었거나 위조된 사본일 수 있습니다. 다른 PC가 새 사본을 올리면 다시 이어집니다.",
        "The server copy names an old key of this PC's but does not open with it, so sync stopped. It may be damaged or forged. Sync resumes when another PC uploads a new copy.",
    ),
    (
        "그럴 PC가 없다면 '열쇠 관리'에서 서버 사본을 이 PC 상태로 덮어쓸 수 있습니다. 이 PC의 변경은 이 PC에 저장되어 있습니다.",
        "If there is no such PC, you can overwrite the server copy with this PC's state in 'Key management'. This PC's changes are saved on this PC.",
    ),
    (
        "이 PC는 이 PC가 전에 쓴 것보다 오래된 열쇠 파일로 열려 있어 동기화를 멈췄습니다. 서버 사본은 합치지도 덮어쓰지도 않습니다. 이 PC가 전에 쓴 최신 열쇠 파일(열쇠 백업)로 다시 열거나 '열쇠 관리 › 새 열쇠 파일 받기'로 그 파일을 받으세요.",
        "This PC is open with a key file older than the one it wrote before, so sync stopped. The server copy is neither merged nor overwritten. Open the vault again with the latest key file this PC wrote (a key backup), or take that file with 'Key management › Receive a new key file'.",
    ),
    (
        "지금 열쇠 파일이 맞다면 '열쇠 관리'에서 [이 열쇠 파일이 맞습니다]를 누르세요. 이 PC의 변경은 이 PC에 저장되어 있습니다.",
        "If the current key file is right, press [This key file is right] in 'Key management'. This PC's changes are saved on this PC.",
    ),
    (
        "다른 PC의 열쇠 파일이 이 PC의 것보다 새롭습니다. 동기화를 멈췄습니다. 그 열쇠 파일을 USB로 가져와 '열쇠 관리 › 새 열쇠 파일 받기'로 받으세요. 그 전에는 이 PC에서 열쇠를 바꾸지 마세요.",
        "Another PC's key file is newer than this PC's. Sync stopped. Bring that key file by USB and take it with 'Key management › Receive a new key file'. Do not change the key on this PC before that.",
    ),
    (
        "예전 열쇠로 만든 서버 사본은 합치지 않고 이 PC의 상태로 덮었습니다. 새 열쇠 파일을 아직 받지 않은 PC가 있으면 그 PC에서 '새 열쇠 파일 받기'를 하세요. 그 PC의 변경은 그 뒤에 합쳐집니다.",
        "A server copy made with an old key was overwritten with this PC's state, not merged. If a PC has not taken the new key file yet, use 'Receive a new key file' on that PC. Its changes are merged after that.",
    ),
    (
        "그런 PC가 없다면 예전 열쇠 사본을 가진 누군가가 올린 것일 수 있습니다.",
        "If there is no such PC, someone with an old copy of the key may have uploaded it.",
    ),
    (
        "다른 PC에서 이 금고의 열쇠가 바뀐 것으로 보입니다. 먼저 '새 열쇠 파일 받기'를 하세요. 서버 사본이 위조된 것이 확실할 때만 계속하세요. 계속하면 두 PC의 열쇠가 갈라져 나중에 '새 열쇠 파일 받기'로 합쳐야 합니다. 그래도 계속할까요?",
        "This vault's key seems to have been changed on another PC. First use 'Receive a new key file'. Continue only if you are sure the server copy is forged. If you continue, the two PCs' keys diverge and must be joined later with 'Receive a new key file'. Continue anyway?",
    ),
    (
        "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라진 것으로 보입니다. 먼저 '새 열쇠 파일 받기'로 다른 PC의 열쇠 파일을 받아 합치세요. 서버 사본이 위조된 것이 확실할 때만 계속하세요. 계속하면 열쇠 파일이 더 갈라져 나중에 '새 열쇠 파일 받기'로 합쳐야 합니다. 그래도 계속할까요?",
        "Two PCs seem to have changed the key separately, so the key files diverged. First take the other PC's key file with 'Receive a new key file' to join them. Continue only if you are sure the server copy is forged. If you continue, the key files diverge further and must be joined later with 'Receive a new key file'. Continue anyway?",
    ),
    (
        "서버의 최신 사본(수정 {epoch}, 열쇠 {key}, 서버 버전 {v})을 이 PC의 상태로 덮어씁니다. 그 사본은 합치지 않고 서버 기록에만 남습니다. 다른 PC에서 열쇠를 바꾼 것이 맞다면 덮어쓰지 말고 그 PC의 열쇠 파일을 받으세요.",
        "This overwrites the server's latest copy (revision {epoch}, key {key}, server version {v}) with this PC's state. That copy is not merged; it stays only in the server history. If another PC really changed the key, do not overwrite: take that PC's key file instead.",
    ),
    (
        "그 PC를 더 쓸 수 없거나 위조된 사본이 확실할 때만 계속하세요. 다른 PC에 더 새 열쇠 파일이 있다면 그 PC는 이후 이 PC의 사본을 예전 열쇠 사본으로 보고 덮어씁니다.",
        "Continue only if that PC can no longer be used, or you are sure the copy is forged. If another PC has a newer key file, it will later treat this PC's copy as an old-key copy and overwrite it.",
    ),
    (
        "서버의 최신 사본(수정 {epoch}, 열쇠 {key}, 서버 버전 {v})을 이 PC의 상태로 덮어씁니다. 그 사본은 합치지 않고 서버 기록에만 남습니다. 다른 PC에서 열쇠를 바꾼 것이 맞다면 덮어쓰지 말고 그 PC의 열쇠 파일을 받으세요.\r\n그 PC를 더 쓸 수 없거나 위조된 사본이 확실할 때만 계속하세요. 다른 PC에 더 새 열쇠 파일이 있다면 그 PC는 이후 이 PC의 사본을 예전 열쇠 사본으로 보고 덮어씁니다.",
        "This overwrites the server's latest copy (revision {epoch}, key {key}, server version {v}) with this PC's state. That copy is not merged; it stays only in the server history. If another PC really changed the key, do not overwrite: take that PC's key file instead.\r\nContinue only if that PC can no longer be used, or you are sure the copy is forged. If another PC has a newer key file, it will later treat this PC's copy as an old-key copy and overwrite it.",
    ),
    (
        "멈춘 동기화가 없어 덮어쓸 서버 사본이 없습니다.",
        "Sync is not stopped, so there is no server copy to overwrite.",
    ),
    (
        "확인한 뒤에 서버의 최신 사본이 바뀌어 덮어쓰지 않았습니다. 처음부터 다시 하세요.",
        "The server's latest copy changed after it was checked, so it was not overwritten. Start over.",
    ),
    (
        "열쇠를 바꿉니다. 새 데이터 키로 금고를 다시 암호화하고 새 열쇠 파일을 씁니다.\n• 바꾼 뒤에는 예전 열쇠 파일과 예전 비밀번호(또는 뺀 보안 키)로 앞으로 저장하는 내용을 열 수 없습니다. 바꾸기 전에 만든 백업과 서버의 예전 버전은 예전 열쇠 사본으로 계속 열립니다.\n• 0.8 이하 버전에서는 이 금고를 열 수 없게 됩니다.\n• 끝나면 새 열쇠 파일을 백업하세요.\n계속할까요?",
        "This changes the key: the vault is encrypted again with a new data key, and a new key file is written.\n• Afterwards the old key file and old password (or a removed security key) cannot open what you save from now on. Backups made before the change and older versions on the server still open with an old key copy.\n• Version 0.8 and older can no longer open this vault.\n• When it is done, back up the new key file.\nContinue?",
    ),
    (
        "열쇠를 바꿉니다. 새 데이터 키로 금고를 다시 암호화하고 새 열쇠 파일을 씁니다.\n• 바꾼 뒤에는 예전 열쇠 파일과 예전 비밀번호(또는 뺀 보안 키)로 앞으로 저장하는 내용을 열 수 없습니다. 바꾸기 전에 만든 백업과 서버의 예전 버전은 예전 열쇠 사본으로 계속 열립니다.\n• 0.8 이하 버전에서는 이 금고를 열 수 없게 됩니다.\n• 끝나면 새 열쇠 파일을 백업하세요.\n• 동기화 중인 금고입니다. 다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다(USB로 '새 열쇠 파일 받기'). 열쇠는 한 번에 한 PC에서만 바꾸고, 서버 스크립트와 모든 PC(고요 금고·goyo-sync)를 먼저 0.9.0으로 업데이트하세요.\n계속할까요?",
        "This changes the key: the vault is encrypted again with a new data key, and a new key file is written.\n• Afterwards the old key file and old password (or a removed security key) cannot open what you save from now on. Backups made before the change and older versions on the server still open with an old key copy.\n• Version 0.8 and older can no longer open this vault.\n• When it is done, back up the new key file.\n• This vault syncs. Other PCs stop syncing until they take this key file (by USB, with 'Receive a new key file'). Change the key on one PC at a time, and first update the server script and every PC (Goyo Vault and goyo-sync) to 0.9.0.\nContinue?",
    ),
    (
        "열쇠 파일이 바뀌었습니다. 새 열쇠 파일을 지금 백업할까요?\n이제 금고를 여는 데 필요한 것은 이 새 열쇠 파일입니다. 예전 '열쇠 백업'으로는 앞으로 저장하는 항목을 열 수 없으니, 이 PC나 열쇠 파일을 잃을 때를 대비해 새 사본을 USB 등 금고와 다른 곳에 두세요.",
        "The key file changed. Back up the new key file now?\nThe vault now opens with this new key file. An older key backup cannot open what you save from now on, so keep a new copy away from the vault (on a USB drive, for example) in case you lose this PC or the key file.",
    ),
    (
        "열쇠 파일을 저장했는지 확인하지 못했습니다. 잠그기 전에 새 열쇠 파일을 다른 저장장치에 저장하세요. 그 파일과 새 비밀번호(와 보안 키)로 이 금고를 열 수 있습니다.\n지금 저장할까요?",
        "Could not confirm that the key file was saved. Before the vault locks, save the new key file to another drive. That file and the new password (and security key) open this vault.\nSave it now?",
    ),
    (
        "열쇠 확인 코드: {code}. 다른 PC에서 새 열쇠 파일을 받은 뒤 그 PC의 코드와 같은지 비교하세요.",
        "Key check code: {code}. Once another PC has taken the new key file, check that its code is the same.",
    ),
    (
        "받을 열쇠 파일은 다른 비밀번호로 잠겨 있습니다. 그 PC에서 바꾼 새 비밀번호를 입력하세요.",
        "The key file to receive is locked with another password. Enter the new password set on that PC.",
    ),
    (
        "이 열쇠 파일은 이 PC의 열쇠 파일에서 이어진 새 버전입니다. 그대로 받습니다.",
        "This key file is a newer version that continues this PC's key file. It is taken as it is.",
    ),
    (
        "이 열쇠 파일은 이 PC의 열쇠 파일과 갈라졌거나, 이 PC에서 추가한 것이 빠져 있습니다. 두 파일을 합치고 새 데이터 키(보안 키가 있으면 새 키세트 비밀도)로 금고를 다시 암호화합니다. 다른 PC는 그 뒤 이 PC의 열쇠 파일을 받아야 합니다.",
        "This key file has diverged from this PC's key file, or lacks something added on this PC. The two files are joined, and the vault is encrypted again with a new data key (with security keys, also a new keyset secret). Other PCs must then take this PC's key file.",
    ),
    (
        "받은 뒤의 열쇠 파일: 수정 {epoch}",
        "Key file afterwards: revision {epoch}",
    ),
    (
        "받은 뒤의 열쇠 확인 코드: {code}",
        "Key check code afterwards: {code}",
    ),
    (
        "앞으로도 이 PC의 비밀번호로 엽니다.",
        "The vault still opens with this PC's password.",
    ),
    (
        "앞으로는 가져온 열쇠 파일의 비밀번호로 엽니다.",
        "From now on the vault opens with the received key file's password.",
    ),
    ("이 PC의 비밀번호 쓰기", "Use this PC's password"),
    (
        "두 PC에서 모두 비밀번호를 바꿨습니다. 앞으로 쓸 비밀번호를 정하세요. '이 PC의 비밀번호 쓰기'를 켜면 이 PC의 비밀번호를, 끄면 가져온 열쇠 파일의 비밀번호를 씁니다. 다른 PC는 받을 때 그 비밀번호를 입력합니다. 이대로 받을까요?",
        "Both PCs changed the password. Choose the password to use from now on: with 'Use this PC's password' ticked, this PC's password; unticked, the received key file's password. Other PCs enter that password when they take the key file. Receive it like this?",
    ),
    (
        "서버 사본 대신 이 PC의 상태를 올립니다. goyo-sync가 올리면 동기화가 다시 이어집니다.",
        "This PC's state is uploaded in place of the server copy. Sync resumes once goyo-sync has uploaded it.",
    ),
    (
        "지금 열쇠 파일을 이 금고의 열쇠 파일로 정했습니다. 동기화와 열쇠 변경을 다시 할 수 있습니다.",
        "The current key file is now this vault's key file. Sync and key changes work again.",
    ),
    (
        "서버 사본이 더 나중의 열쇠로 저장되어 있으면 동기화가 다시 멈춥니다. 그 사본을 이 PC가 올렸다면 [서버 사본을 이 PC 상태로 덮어쓰기…]를 누르세요.",
        "If the server copy was saved under a later key, sync stops again. If this PC uploaded that copy, press [Overwrite the server copy with this PC's state…].",
    ),
    (
        "끝나지 않은 열쇠 변경 버리기…",
        "Discard the unfinished key change…",
    ),
    ("이 열쇠 파일이 맞습니다", "This key file is right"),
    (
        "서버 사본 때문에 동기화가 멈춰 있습니다. 그 사본을 올린 PC의 열쇠 파일을 받을 수 없을 때만 서버 사본을 덮어쓰세요.",
        "A server copy has stopped sync. Overwrite the server copy only if the key file of the PC that uploaded it cannot be received.",
    ),
    (
        "서버 사본을 이 PC 상태로 덮어쓰기…",
        "Overwrite the server copy with this PC's state…",
    ),
    ("열쇠 관리", "Key management"),
    (
        "다른 PC에서 비밀번호를 바꿨다면 그 PC의 새 열쇠 파일을 USB로 가져와 '새 열쇠 파일 받기'로 받으세요. 이 PC의 열쇠 파일 위에 덮어쓰지 마세요.",
        "If another PC changed the password, bring that PC's new key file by USB and take it with 'Receive a new key file'. Do not copy it over this PC's key file.",
    ),
    ("비밀번호 변경…", "Change password…"),
    ("다른 PC의 열쇠 파일", "Another PC's key file"),
    ("새 열쇠 파일 받기…", "Receive a new key file…"),
    ("열쇠 확인 코드", "Key check code"),
    (
        "두 PC의 열쇠 확인 코드가 같으면 같은 열쇠 파일입니다. 열쇠를 바꾼 뒤 다른 PC에서 새 열쇠 파일을 받았다면 두 코드를 비교하세요.",
        "Two PCs that show the same key check code have the same key file. After a key change, once another PC has taken the new key file, compare the two codes.",
    ),
    ("새 열쇠 파일 받기", "Receive a new key file"),
    (
        "다른 PC에서 바꾼 열쇠 파일을 이 PC의 열쇠 파일과 비교합니다. 이어진 새 버전이면 그대로 받고, 갈라졌으면 두 파일을 합칩니다. 받기 전에 무엇이 바뀌는지 보여 줍니다.",
        "The key file changed on another PC is compared with this PC's. A newer version that continues it is taken as it is; a diverged one is joined with it. You see what changes before anything is taken.",
    ),
    ("받을 열쇠 파일", "Key file to receive"),
    ("0.8 형식 열쇠 파일", "Key file in the 0.8 format"),
    ("열쇠 파일 수정 {epoch}", "Key file revision {epoch}"),
    (
        "본인 확인: 이 PC의 현재 비밀번호",
        "Verify it's you: this PC's current password",
    ),
    ("열기", "Open"),
    (
        "받을 열쇠 파일의 비밀번호가 이 PC와 다르면 열 때 그 비밀번호를 묻습니다.",
        "If the key file to receive has another password than this PC's, you are asked for it when it is opened.",
    ),
    (
        "받을 열쇠 파일을 고르세요.",
        "Choose the key file to receive.",
    ),
    ("확인", "OK"),
    ("받기", "Accept"),
];
/// The English of the security-key build's own texts (spec §9.3): only that
/// build compiles them, so the default exe holds none of them.
#[cfg(feature = "security-key")]
pub const EN_SK: &[(&str, &str)] = &[
    // The server's key file at login and from Restore (spec §5.2, §7.17).
    (
        "열리지 않았습니다. 다른 PC에서 비밀번호를 바꿨다면 서버에 온 새 열쇠 파일로 열 수 있습니다. 서버의 새 열쇠 파일로 열어 볼까요?",
        "It did not open. If the password was changed on another PC, the new key file that came from the server can open it. Try the server's new key file?",
    ),
    (
        "보안 키 확인을 취소해서 이 PC의 열쇠 파일로는 열어 보지 않았습니다. 서버에서 받아 둔 열쇠 파일(아직 확인 전)에는 이 PC가 모르는 보안 키가 들어 있습니다. 다른 PC에서 새로 등록해 이 PC로 가져온 키가 있다면 그 키로 열어 볼까요? 그런 키를 가져온 적이 없다면 취소하고 이 PC의 보안 키로 다시 여세요.",
        "The security key check was cancelled, so this PC's key file was not tried. The key file received from the server (not confirmed yet) holds a security key this PC does not know. If you brought a key here that was newly registered on another PC, try it? If you never brought such a key, cancel and open again with this PC's security key.",
    ),
    (
        "서버에서 받아 둔 열쇠 파일이 이 보안 키와 입력한 비밀번호(와 OTP)로 열리지 않았습니다. 이 PC의 열쇠 파일에 등록된 보안 키로 다시 여세요. 다른 PC에서 키를 가져온 적이 없다면 서버의 열쇠 파일이 위조되었을 수 있습니다.",
        "The key file received from the server did not open with this security key and the password (and OTP) entered. Open again with a security key registered in this PC's key file. If you never brought a key from another PC, the server's key file may be forged.",
    ),
    (
        "다른 PC의 열쇠 변경을 받았습니다. 열쇠 확인 코드 {code}",
        "Took another PC's key change. Key check code {code}",
    ),
    ("확인 전에는 이 열쇠 파일과 금고를 이 PC에 저장하지도 않습니다. 확인하면 열쇠 파일을 금고 옆에 저장합니다.", "Until then, neither this key file nor the vault is saved on this PC. Once confirmed, the key file is saved next to the vault."),
    ("서버에서 받은 이 열쇠 파일은 이 PC가 이미 확인했습니다. 남은 일은 이 PC에 저장하는 것뿐입니다. '저장하기'를 누르세요.", "This PC already confirmed this key file from the server. All that is left is saving it on this PC: press 'Save'."),
    ("저장하기", "Save"),
    ("서버에서 가져온 열쇠 파일 확인", "Confirm the key file from the server"),
    ("열쇠 파일을 {path}에 저장했습니다. 이제 항목을 고치고 저장할 수 있고, 다음부터는 이 열쇠 파일로 엽니다. 이 PC의 서버 동기화도 지금 시작했습니다.", "Saved the key file to {path}. You can now edit and save entries, and from now on the vault opens with this key file. Syncing with the server has started on this PC too."),
    ("열쇠 파일을 금고 옆에 저장합니다:\n{path}\n\n이 PC에서 금고를 열 때마다 이 열쇠 파일이 필요합니다. 다른 곳(USB 등)에 두려면 '다른 곳에 저장…'을 누르세요.", "The key file is saved next to the vault:\n{path}\n\nOpening the vault on this PC always needs this key file. To keep it elsewhere (on a USB drive, for example), press 'Save elsewhere…'."),
    ("코드가 맞습니다. 이 열쇠 파일은 진짜입니다.", "The code matches: this key file is genuine."),
    ("코드 없이 이 서버를 믿기로 했습니다. 이 열쇠 파일이 진짜인지는 확인하지 않았습니다.", "You chose to trust this server without a code. Whether this key file is genuine was not checked."),
    ("이 PC가 이미 확인한 열쇠 파일입니다.", "This PC already confirmed this key file."),
    ("여기에 저장", "Save here"),
    ("다른 곳에 저장…", "Save elsewhere…"),
    ("아직 저장하지 않았습니다. 준비되면 '코드 확인'을 다시 누르세요(코드는 그대로 둡니다).", "Not saved yet. When you are ready, press 'Check code' again (the code stays in its field)."),
    ("저장할 곳을 고르는 창을 열지 못했습니다. 아무것도 저장하지 않았습니다. '코드 확인'을 다시 누르고 '여기에 저장'을 고르세요.", "The dialog to choose where to save could not open. Nothing was saved. Press 'Check code' again and choose 'Save here'."),
    ("아직 저장하지 않았습니다. 준비되면 '코드 없이 받기…'를 다시 누르거나, 다른 PC의 코드를 입력하고 '코드 확인'을 누르세요.", "Not saved yet. When you are ready, press 'Accept without a code…' again, or type another PC's code and press 'Check code'."),
    ("아직 저장하지 않았습니다. 준비되면 '저장하기'를 다시 누르세요.", "Not saved yet. When you are ready, press 'Save' again."),
    ("저장할 곳을 고르는 창을 열지 못했습니다. 아무것도 저장하지 않았습니다. '코드 없이 받기…'를 다시 누르고 '여기에 저장'을 고르세요.", "The dialog to choose where to save could not open. Nothing was saved. Press 'Accept without a code…' again and choose 'Save here'."),
    ("저장할 곳을 고르는 창을 열지 못했습니다. 아무것도 저장하지 않았습니다. '저장하기'를 다시 누르고 '여기에 저장'을 고르세요.", "The dialog to choose where to save could not open. Nothing was saved. Press 'Save' again and choose 'Save here'."),
    ("먼저 위의 확인을 끝내세요(다른 PC의 열쇠 확인 코드 입력, 또는 '저장하기'). 그 전에는 백업하거나 열쇠를 관리하지 않습니다.", "Finish the step above first (another PC's key check code, or 'Save'). Until then, nothing is backed up and the keys are not managed."),
    ("동기화 폴더 안의 그 파일은 서버에서 받은 열쇠 파일(확인 전)이라 여기서는 쓰지 않습니다. 그 금고 파일은 아래의 '서버에서 가져온 금고로 열기'(또는 시작 화면의 '금고 파일 열기')로 여세요.", "That file in the sync folder is the key file received from the server (not confirmed yet), so it is not used here. Open that vault file with 'Open as a vault from the server' below (or 'Open a vault file' on the start screen)."),
    ("이 파일은 서버에서 가져온 금고입니다. 이 PC에 아직 열쇠 파일이 없으니 백업처럼 되살리지 말고 아래 버튼으로 여세요.", "This file is a vault brought from the server. This PC has no key file for it yet, so do not restore it like a backup: open it with the button below."),
    ("서버에서 가져온 금고로 열기", "Open as a vault from the server"),
    ("이 파일은 서버에서 가져온 금고입니다. 아래의 '서버에서 가져온 금고로 열기'를 누르세요.", "This file is a vault brought from the server. Press 'Open as a vault from the server' below."),
    ("이 열쇠 파일은 서버로 동기화됩니다. 다른 PC에서 비밀번호나 열쇠를 바꾸면 아래 열쇠 파일 줄에 [받기…]가 나타납니다. USB로 가져온 열쇠 파일을 이 PC의 열쇠 파일 위에 덮어쓰지 마세요.", "This key file syncs through the server. When another PC changes the password or the keys, [Get…] appears on the key file line below. Do not copy a key file from a USB drive over this PC's key file."),
    (
        "열쇠 파일을 저장할 곳을 고르세요 (동기화 폴더 밖)",
        "Choose where to save the key file (outside the sync folder)",
    ),
    ("서버에서 가져온 금고", "Vault brought from the server"),
    ("goyo-sync가 서버에서 이 금고와 그 열쇠 파일을 가져왔습니다. 열쇠 파일은 아직 이 PC에 저장되지 않았고, 다른 PC의 코드로 확인하기 전에는 믿지 않습니다.\n{step}\n② 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력합니다.\n③ 열쇠 파일을 금고 옆에 {name}(으)로 저장합니다.", "goyo-sync brought this vault and its key file from the server. The key file is not saved on this PC yet and is not trusted until another PC's code confirms it.\n{step}\n② Type the key check code shown under 'Key management' on another PC.\n③ The key file is saved next to the vault as {name}."),
    ("① 비밀번호를 입력하고 '다음'을 누른 뒤 보안 키를 터치합니다.", "① Type the password, press 'Next' and touch your security key."),
    ("① 비밀번호를 입력하고 '다음'을 누릅니다.", "① Type the password and press 'Next'."),
    ("서버에서 가져온 금고 파일", "Vault file from the server"),
    ("다음 · 보안 키 터치", "Next · touch the security key"),
    ("다음", "Next"),
    ("열쇠 파일이 있으면 그것으로 열기", "Open with a key file I have"),
    ("금고 옆에 열쇠 파일이 있습니다. 그 열쇠 파일로 여세요.", "There is a key file next to the vault. Open the vault with it."),
    ("이 금고의 동기화 폴더에 서버에서 받은 열쇠 파일이 없습니다. goyo-sync에서 '이 PC로 가져오기'를 다시 하거나, 다른 PC의 열쇠 파일을 USB로 가져와 금고 옆에 두세요.", "This vault's sync folder holds no key file from the server. Run 'Bring to this PC' in goyo-sync again, or bring another PC's key file by USB and put it next to the vault."),
    ("② 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 오른쪽 칸에 입력하세요.", "② Type the key check code shown under 'Key management' on another PC into the field on the right."),
    ("서버에서 가져온 금고이고, 이 PC에 열쇠 파일이 아직 없습니다. 위 순서대로 여세요.", "This vault came from the server and this PC has no key file for it yet. Open it with the steps above."),
    (
        "서버의 새 열쇠 파일은 이 PC의 열쇠 파일에서 이어진 것이 아니어서 열지 않았습니다. 이 PC의 비밀번호와 보안 키로 연 뒤 '열쇠 관리'를 확인하세요. 그런 변경을 한 적이 없다면 서버의 열쇠 파일이 위조되었을 수 있습니다.",
        "The server's new key file does not follow from this PC's key file, so it was not opened. Open with this PC's password and security key, then check 'Key management'. If no such change was made, the server's key file may be forged.",
    ),
    (
        "서버의 새 열쇠 파일에는 이 PC의 열쇠 파일에 있는 예전 열쇠가 모두 들어 있지 않아 이 방법으로는 열 수 없습니다. 이 PC에서 쓰던 예전 비밀번호로 연 뒤 '열쇠 관리'의 [받기…]로 받으세요.",
        "The server's new key file does not hold every older key of this PC's key file, so it cannot open the vault this way. Open with the old password this PC used, then take it with [Get…] in 'Key management'.",
    ),
    (
        "서버의 열쇠 파일은 이 PC의 열쇠 파일을 바로 이어받은 것이 아니어서 이 방법으로는 받을 수 없습니다. 이 PC에서 쓰던 비밀번호로 연 뒤 '열쇠 관리'의 [받기…]로 받으세요.",
        "The server's key file does not directly follow this PC's key file, so it cannot be taken this way. Open with the password this PC used, then take it with [Get…] in 'Key management'.",
    ),
    (
        "OTP 번호를 입력한 지 3분이 넘었습니다. 새 OTP 번호로 다시 여세요.",
        "More than three minutes passed since the OTP code was entered. Open again with a new OTP code.",
    ),
    (
        "열쇠 파일 동기화를 켜는 열쇠 파일입니다. 받기 전에 확인이 필요합니다.",
        "This key file turns key-file sync on. It needs confirming before it is taken.",
    ),
    (
        "서버의 열쇠 파일이 이 PC의 금고보다 오래되었습니다.",
        "The server's key file is older than this PC's vault.",
    ),
    (
        "서버에서 받은 열쇠 파일이 이 PC가 기록해 둔 이 금고의 열쇠와 맞지 않아 열지 않았습니다. 이 PC의 열쇠 파일(열쇠 백업)로 연 뒤 '열쇠 관리'에서 받으세요.",
        "The key file from the server does not match this PC's record of this vault's keys, so it was not opened. Open with this PC's key file (key backup), then take it in 'Key management'.",
    ),
    (
        "이 금고 파일의 동기화 폴더에 서버에서 받은 열쇠 파일이 없습니다. goyo-sync의 '이 PC로 가져오기…'로 다시 가져오거나, 다른 PC의 열쇠 파일을 USB로 가져와 금고 옆에 두세요.",
        "This vault file's sync folder holds no key file from the server. Bring it again with goyo-sync's 'Bring to this PC…', or bring another PC's key file by USB and put it next to the vault.",
    ),
    (
        "서버에서 받은 열쇠 파일을 이 PC에 저장하기 전에는 항목을 고치거나 저장하지 않습니다. 위 칸의 '코드 확인'(또는 '저장하기')으로 먼저 저장하세요.",
        "Until the key file from the server is saved on this PC, entries are not edited or saved. Save it first with 'Check code' (or 'Save') above.",
    ),
    (
        "열쇠 파일은 동기화 폴더 밖에 저장하세요. 다른 곳을 고르세요.",
        "Save the key file outside the sync folder. Choose another place.",
    ),
    (
        "같은 이름의 파일이 이미 있습니다. 다른 이름을 고르세요.",
        "A file with that name already exists. Choose another name.",
    ),
    (
        "가져왔습니다: {}\n(서버 버전 {}, {}바이트, 서버의 열쇠 파일도 함께 · 아직 확인 전)\n\n다음 순서:\n1. {}\n2. {} '서버에서 가져온 금고' 화면이 이어서 안내합니다.\n3. 비밀번호와 보안 키로 연 뒤, 다른 PC의 고요 금고 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력합니다.\n4. 코드가 맞으면 열쇠 파일이 금고 옆에 {} 이름으로 저장되고, 그때부터 평소처럼 열립니다.",
        "Brought here: {}\n(server version {}, {} bytes, with the server's key file · not confirmed yet)\n\nNext:\n1. {}\n2. Then {} The 'Vault brought from the server' screen guides you from there.\n3. Open it with the password and a security key, then enter the key check code that Goyo Vault's 'Key management' shows on another PC.\n4. If the code matches, the key file is saved next to the vault as {}, and from then on it opens as usual.",
    ),
    (
        "이 PC의 서버 줄이 열쇠 파일 요청을 허용하지 않아 서버에 이 금고의 열쇠 파일이 있는지 알 수 없습니다. 있다면 '강제 명령 줄…'의 줄을 서버에 넣고 '저장하고 시작'을 누르세요. 금고 목록에 '열쇠: 서버에 있음'이 보이면 고요 금고를 다시 열거나 '찾기'로 이 파일을 다시 고르세요. '서버에서 가져온 금고' 화면이 이어서 안내합니다. 아니면:\n",
        "This PC's server line does not allow key file requests, so whether the server holds this vault's key file is unknown. If it does, put the line of 'Forced command line…' on the server and press 'Save and start'. Once the vault list shows 'key: on the server', open Goyo Vault again or choose this file again with 'Browse': the 'Vault brought from the server' screen guides you on. Otherwise:\n",
    ),
    (
        "서버에 이 금고의 열쇠 파일이 없습니다(이 금고는 열쇠 파일을 PC에만 둡니다).\n",
        "The server holds no key file of this vault (this vault keeps its key file on PCs only).\n",
    ),
    (
        "서버의 열쇠 파일은 받지 못했습니다({}).\n",
        "The server's key file did not come ({}).\n",
    ),
    (
        "서버 응답 형식",
        "the server's answer",
    ),
    (
        "파일 쓰기",
        "writing the file",
    ),
    (
        "연결",
        "the connection",
    ),
    // goyo-sync's window (bin/goyo-sync/keys_gui.rs).
    (
        "열쇠: 서버가 허용 안 함 · '강제 명령 줄…'의 줄로 바꾸세요",
        "key: not allowed by the server · use the 'Forced command line…' line",
    ),
    (
        "열쇠: 서버에 있음",
        "key: on the server",
    ),
    (
        "열쇠: 서버에 없음",
        "key: not on the server",
    ),
    (
        "열쇠: 서버가 허용 안 함",
        "key: not allowed by the server",
    ),
    (
        "열쇠 파일: 서버에 있음",
        "key file: on the server",
    ),
    (
        "열쇠 파일: 서버에 없음 (USB로)",
        "key file: not on the server (by USB)",
    ),
    (
        "열쇠 파일: 이 PC 줄로는 확인 안 함",
        "key file: not checked with this PC's line",
    ),
    (
        "이 열쇠 파일을 열 수 있는 보안 키가 보안 키 {n} 하나뿐입니다(나머지는 일시 정지). 이 키를 잃으면 이 금고를 열 수 없습니다. 다른 키와 '짝 맺기'를 하세요.",
        "Only security key {n} can open this key file (the others are suspended). If it is lost, this vault cannot be opened. Pair it with another key.",
    ),
    ("짝 맺기 필요", "needs pairing"),
    (
        "짝 기록 손상: 다시 짝 맺기 필요",
        "pair record damaged: pair it again",
    ),
    ("보안 키: 꺼짐", "Security keys: off"),
    (
        "보안 키: 켜짐 · {n}개 등록",
        "Security keys: on · {n} registered",
    ),
    (
        "보안 키: 켜짐 · PIN 사용 · {n}개 등록",
        "Security keys: on · PIN used · {n} registered",
    ),
    (
        "보안 키 {n} · {date} 등록",
        "Security key {n} · registered {date}",
    ),
    ("이번에 연 키", "used for this unlock"),
    ("등록 표시 {stamp}", "label {stamp}"),
    ("모든 키와 짝", "paired with every key"),
    (
        "보안 키 {list}과(와) 짝 맺기 필요",
        "needs pairing with security key {list}",
    ),
    (
        "짝 기록 손상: 보안 키 {list}과(와) 다시 짝 맺기 필요",
        "pair record damaged: pair again with security key {list}",
    ),
    (
        "짝 기록 없음: 빼고 다시 등록해야 함",
        "no pair record: remove it and register it again",
    ),
    ("일시 정지(짝 맺기 필요)", "suspended (needs pairing)"),
    (
        "복제됐을 수 있음: 모든 키 새로 잠그기나 다시 등록 권장",
        "may have been cloned: re-lock all keys or register it again",
    ),
    (
        "다른 키를 모두 대신할 수 있는 키: 보안 키 {list}",
        "Keys that can stand in for all the others: security key {list}",
    ),
    (
        "다른 키를 모두 대신할 수 있는 키: 없음 ('짝 맺기'를 하세요)",
        "Keys that can stand in for all the others: none (use 'Pair keys')",
    ),
    (
        "보안 키(YubiKey 등 FIDO2)를 켜면 열쇠 파일을 비밀번호와 등록한 보안 키 둘 다로 잠급니다. OTP보다 권하는 방법이 아니라 또 하나의 선택지이며, 실험 기능입니다.\n등록한 키를 모두 잃으면 누구도(만든 사람도) 이 금고를 열 수 없고 복구 방법도 없으니 2개 이상 등록하세요. 키는 한 PC에서 함께 등록해야 서로 짝을 맺고, 하나를 잃어도 남은 키 하나로 바로 뺄 수 있습니다. 키마다 PIN을 다르게 정하고, 키 번호를 실물 키에 적어 두세요.",
        "With security keys on (YubiKey or another FIDO2 key), the key file is locked with both the password and a registered security key. This is not recommended over the OTP; it is another option, and experimental.\nIf every registered key is lost, no one (not even you) can open this vault, and there is no recovery, so register two or more. Keys registered together on one PC are paired, so if one is lost the other alone can remove it at once. Give each key its own PIN, and write the key number on each key.",
    ),
    (
        "다른 PC에서 이 금고의 보안 키 추가나 설정 변경을 받을 때 이 코드를 입력합니다.",
        "Another PC enters this code when it takes an added security key or a settings change of this vault.",
    ),
    ("보안 키 켜기", "Turn on security keys"),
    (
        "비밀번호도 바꾸기 (권장)",
        "Also change the password (recommended)",
    ),
    ("키 추가", "Add key"),
    ("짝 맺기…", "Pair keys…"),
    ("모든 키 새로 잠그기…", "Re-lock all keys…"),
    ("보안 키 끄기", "Turn off keys"),
    (
        "이 열쇠 파일은 아직 '열쇠 백업'으로 백업하지 않았습니다. 열쇠 파일을 잃으면 보안 키와 비밀번호가 있어도 열 수 없습니다.",
        "This key file has not been backed up with 'Back up key' yet. If the key file is lost, the vault cannot be opened even with the security keys and the password.",
    ),
    (
        "보안 키로도 잠그기 (실험)",
        "Security keys too (experimental)",
    ),
    (
        "열 때마다 등록한 보안 키를 연결하고 터치하고 키의 PIN을 입력합니다. 모두 잃으면 누구도 복구할 수 없으니 2개 이상, 지금 함께 등록하세요(함께 등록한 키끼리 짝을 맺습니다). 등록할 때 키마다 Windows 창이 세 번 열립니다. PIN이 없는 키는 그때 PIN을 정하며, 키마다 PIN을 다르게 정하세요.",
        "Each unlock needs a registered security key connected and touched, and the key's PIN entered. If all are lost, no one can recover the vault, so register two or more now (keys registered together are paired). Each key's registration opens a Windows window three times. A key without a PIN gets one then; give each key its own PIN.",
    ),
    (
        "보안 키 없이 비밀번호와 열쇠 파일로 여는 금고를 만듭니다.",
        "Creates a vault that opens with the password and key file, without security keys.",
    ),
    (
        "보안 키 {n} 등록: Windows 창이 세 번 열립니다(등록 1번, 확인 2번). 매번 키를 터치하고 PIN을 입력하세요. PIN이 없는 키는 첫 창에서 PIN을 정합니다. NFC 리더에 댈 키는 먼저 USB에서 뽑으세요.",
        "Registering security key {n}: a Windows window opens three times (registration once, check twice). Touch the key and enter its PIN each time. A key without a PIN gets one in the first window. Unplug a key from USB before holding it to an NFC reader.",
    ),
    (
        "키마다 다른 PIN을 쓰세요. 모든 키에 같은 PIN을 쓰면, 잃어버린 키와 그 PIN을 아는 사람이 다른 키를 잠깐 손에 넣는 것만으로 그 키를 복제할 수 있습니다.",
        "Use a different PIN on each key. With the same PIN on every key, someone with a lost key and its PIN can copy another key by getting hold of it for a moment.",
    ),
    (
        "보안 키 {n}개를 등록했습니다. 등록한 키를 모두 잃으면 누구도(만든 사람도) 이 금고를 열 수 없고 복구 방법도 없습니다.\n예비 키를 지금 등록할까요? (강력 권장) 지금 함께 등록한 키끼리 짝을 맺어, 나중에 하나를 잃어도 남은 키 하나로 바로 뺄 수 있습니다.",
        "Security keys registered so far: {n}. If every registered key is lost, no one (not even you) can open this vault, and there is no recovery.\nRegister a spare key now? (Strongly recommended) Keys registered together now are paired, so if one is lost later the other alone can remove it at once.",
    ),
    (
        "예비 키 없이 계속할까요? 나중에 '열쇠 관리 › 키 추가'로 등록할 수 있습니다.",
        "Continue without a spare key? You can register one later with 'Key management › Add key'.",
    ),
    (
        "보안 키가 1개뿐입니다. 이 키를 잃거나 초기화하면 비밀번호와 열쇠 파일이 있어도 누구도 이 금고를 열 수 없습니다. '열쇠 관리'에서 예비 키를 추가하세요.",
        "Only one security key. If it is lost or reset, no one can open this vault, even with the password and key file. Add a spare key in 'Key management'.",
    ),
    (
        "새 금고를 만들었습니다. 보안 키 {n}개가 등록되었고 서로 짝을 맺었습니다. 아래 '열쇠 백업'으로 열쇠 파일 사본을 따로 두세요.",
        "New vault created. {n} security keys are registered and paired with each other. Keep a copy of the key file elsewhere with 'Back up key' below.",
    ),
    (
        "확인한 지 오래되어 더 등록하지 않았습니다. 나머지 키는 '키 추가'로 등록하세요.",
        "The check is too old for another registration. Register the other keys with 'Add key'.",
    ),
    (
        "확인한 지 오래되어 한 번 더 확인합니다. 새 OTP 코드를 입력하세요. 지금까지 등록하거나 터치한 키는 그대로 씁니다.",
        "It has been a while, so we check once more. Enter a new OTP code. The keys registered or touched so far are kept.",
    ),
    (
        "확인한 지 오래되어 한 번 더 확인합니다. 보안 키 {n}을(를) 다시 터치하세요. 지금까지 등록하거나 터치한 키는 그대로 씁니다.",
        "It has been a while, so we check once more. Touch security key {n} again. The keys registered or touched so far are kept.",
    ),
    (
        "확인한 지 오래되어 한 번 더 확인합니다. 새 OTP 코드를 입력한 뒤 보안 키 {n}을(를) 다시 터치하세요. 지금까지 등록하거나 터치한 키는 그대로 씁니다.",
        "It has been a while, so we check once more. Enter a new OTP code, then touch security key {n} again. The keys registered or touched so far are kept.",
    ),
    (
        "비밀번호를 그대로 두면, 보안 키를 켜기 전에 만든 열쇠 파일과 그 백업(비밀번호만으로 열림)을 가진 사람은 누구나 이 비밀번호를 오프라인으로 계속 추측할 수 있고, 맞히면 남은 것은 등록한 보안 키(와 PIN)뿐입니다. 그 사본들을 지우거나 비밀번호도 바꾸세요.",
        "If the password stays, anyone with a key file made before security keys were on, or its backup (which opens with the password alone), can keep guessing this password offline, and once it is guessed only the registered keys (and PIN) remain. Delete those copies or change the password too.",
    ),
    (
        "보안 키를 켜면 앞으로 이 금고를 열 때마다 비밀번호와 함께, 등록한 보안 키 하나를 연결해 터치하고 그 키의 PIN을 입력합니다.\n• 등록할 보안 키를 모두 지금 이 PC에 준비하세요(2개 이상 권장). 키마다 Windows 창이 세 번 열립니다.\n• 이 금고를 다른 PC에서도 쓴다면, 그 PC의 고요 금고도 보안 키 빌드여야 하고 끝난 뒤 그 PC마다 이 PC의 새 열쇠 파일을 받아야 합니다.",
        "With security keys on, every time this vault is opened you also plug in one registered security key, touch it and enter its PIN, besides the password.\n• Have every key you will register at this PC now (2 or more recommended). Windows opens three windows per key.\n• If you also use this vault on other PCs, Goyo Vault there must be the security-key build too, and afterwards each of those PCs must take this PC's new key file.",
    ),
    (
        "다른 PC에서도 이 금고를 쓴다면, 그 PC마다 이 PC의 새 열쇠 파일을 USB로 가져가 '열쇠 관리 › 새 열쇠 파일 받기'로 받고, 이 PC의 열쇠 확인 코드를 입력한 뒤 등록한 보안 키 하나를 터치하세요. 그 PC의 고요 금고는 보안 키 빌드여야 합니다.",
        "If you also use this vault on other PCs: on each of them, bring this PC's new key file by USB, take it with 'Key management › Receive a new key file', enter this PC's key check code and touch one registered security key. Goyo Vault there must be the security-key build.",
    ),
    (
        "동기화 중인 금고입니다. 다른 PC는 이 PC의 새 열쇠 파일을 받을 때까지 동기화를 멈춥니다. 그 PC마다 이 열쇠 파일을 USB로 가져가 '열쇠 관리 › 새 열쇠 파일 받기'로 받고, 이 PC의 열쇠 확인 코드를 입력한 뒤 등록한 보안 키 하나를 터치하세요. 그 PC의 고요 금고는 보안 키 빌드여야 합니다.\n이 PC에서 열쇠 파일 동기화도 켜면, 그 PC는 USB 대신 '열쇠 관리'의 '서버의 새 열쇠 파일 받기…'로 받을 수 있습니다.",
        "This vault syncs. The other PCs stop syncing until they take this PC's new key file. On each of them, bring this key file by USB, take it with 'Key management › Receive a new key file', enter this PC's key check code and touch one registered security key. Goyo Vault there must be the security-key build.\nIf you also turn key-file sync on at this PC, those PCs can take it with 'Receive the new key file from the server…' in 'Key management' instead of by USB.",
    ),
    (
        "서버의 새 열쇠 파일 받기…",
        "Receive the new key file from the server…",
    ),
    (
        "다른 PC에서 보안 키를 켠 새 열쇠 파일(수정 {e})이 서버에 있습니다. 받아야 그 PC와 다시 동기화됩니다.\r\n현재 비밀번호(와 OTP)를 넣고 '서버의 새 열쇠 파일 받기…'를 누른 뒤, 그 PC의 열쇠 확인 코드를 입력하고 새 열쇠 파일에 등록된 보안 키 하나를 터치하세요. 그 PC의 코드를 볼 수 없으면 '코드 없이 이 서버를 믿고 받기…'를 고를 수 있습니다. 보안 키를 켠 PC가 없다면 받지 마세요(서버 사본이 위조되었을 수 있습니다).",
        "The server holds a new key file (revision {e}) from another PC that turned security keys on. Take it to sync with that PC again.\r\nEnter your current password (and OTP), press 'Receive the new key file from the server…', enter that PC's key check code and touch one security key registered in the new key file. If you cannot see that PC's code, you can choose 'Trust this server and take it without a code…'. If no PC turned security keys on, do not take it (the server copy may be forged).",
    ),
    (
        "코드 없이 이 서버를 믿고 받기…",
        "Trust this server and take it without a code…",
    ),
    (
        "다른 PC의 열쇠 확인 코드 없이는 이 열쇠 파일을 정말 그 PC에서 만들었는지 확인할 방법이 없습니다.\n서버를 장악하고 이 금고의 비밀번호를 아는 사람이 자기 보안 키로 만든 열쇠 파일일 수 있고, 그렇다면 그 사람은 앞으로 이 PC에서 저장하는 내용을 읽을 수 있습니다. 그 PC의 코드를 볼 수 없을 때만 하세요. 코드 없이 서버의 열쇠 파일을 받을까요?",
        "Without the other PC's key check code there is no way to check that this key file really was made on that PC.\nSomeone who took over the server and knows this vault's password could have made it with their own security key, and could then read what this PC saves from now on. Do this only if you cannot see that PC's code. Take the server's key file without a code?",
    ),
    (
        "코드 없이 이 서버를 믿고 받았습니다. 이 열쇠 파일이 진짜인지는 확인하지 않았습니다. 그 PC를 다시 쓸 수 있으면 두 PC의 열쇠 확인 코드가 같은지 비교하세요.",
        "Taken without a code, trusting this server. Whether this key file is genuine was not checked. When you can use that PC again, compare the two PCs' key check codes.",
    ),
    (
        "다른 PC에서 이 금고에 보안 키를 켜 동기화를 멈췄습니다. 새 열쇠 파일은 서버로 옵니다. '열쇠 관리'의 '서버의 새 열쇠 파일 받기…'로 받으세요(그 PC의 열쇠 확인 코드와 새 열쇠 파일의 보안 키 하나가 필요합니다).",
        "Another PC turned security keys on for this vault, so sync stopped. The new key file comes through the server: take it with 'Receive the new key file from the server…' in 'Key management' (you need that PC's key check code and one security key of the new key file).",
    ),
    (
        "그런 PC가 없다면 서버 사본이 위조되었을 수 있습니다. 그때까지 이 PC의 변경은 이 PC에만 저장됩니다.",
        "If no PC did, the server copy may be forged. Until then, this PC's changes are saved on this PC only.",
    ),
    (
        "보안 키를 켰습니다. 보안 키 {n}개가 등록되었고 서로 짝을 맺었습니다.",
        "Security keys are on. {n} security keys are registered and paired with each other.",
    ),
    (
        "앞으로는 이번에 새로 정한 비밀번호로 엽니다.",
        "From now on, it opens with the new password you just set.",
    ),
    (
        "지금 꽂혀 있는 다른 보안 키가 있으면 함께 터치해 새 키와 짝을 맺으세요(키마다 한 번).\n다른 장소의 키와는 나중에 '짝 맺기'를 하면 됩니다. 지금 다른 키를 터치할까요?",
        "If another security key is plugged in now, touch it too to pair it with the new key (once per key).\nKeys kept elsewhere can be paired later with 'Pair keys'. Touch another key now?",
    ),
    (
        "짝을 맺을 보안 키를 연결하고 터치하세요.",
        "Connect and touch the security key to pair.",
    ),
    ("보안 키 {n}을(를) 추가했습니다.", "Security key {n} added."),
    (
        "새 열쇠 파일을 지금 백업할까요?",
        "Back up the new key file now?",
    ),
    (
        "다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다. 다른 PC에서 '새 열쇠 파일 받기'로 이 열쇠 파일을 받고, 이 PC의 열쇠 확인 코드를 입력하세요.",
        "Other PCs pause sync until they take this key file. On each other PC, take it with 'Receive a new key file' and enter this PC's key check code.",
    ),
    (
        "다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다. 다른 PC에서 '새 열쇠 파일 받기'로 이 열쇠 파일을 받으세요(코드는 필요 없습니다).",
        "Other PCs pause sync until they take this key file. On each other PC, take it with 'Receive a new key file' (no code needed).",
    ),
    ("짝 맺기", "Pair keys"),
    (
        "함께 꽂아 차례로 터치하면 서로 짝을 맺습니다. 짝을 맺은 키끼리는 서로를 대신해 새 열쇠를 전할 수 있어, 하나를 잃어도 남은 키 하나로 바로 뺄 수 있습니다. 일시 정지된 키도 여기서 다시 쓰게 됩니다.",
        "Plug the keys in together and touch them in turn to pair them. Paired keys can pass a new key on for each other, so if one is lost the other alone can remove it at once. A suspended key works again after this.",
    ),
    (
        "짝을 맺을 보안 키를 두 개 이상 고르세요.",
        "Choose two or more security keys to pair.",
    ),
    ("보안 키 {n}", "Security key {n}"),
    (
        "짝을 맺을 보안 키 {n}을(를) 연결하고 터치하세요. ({i}/{m})",
        "Connect and touch security key {n} to pair. ({i}/{m})",
    ),
    (
        "보안 키 {list}이(가) 서로 짝을 맺었습니다.",
        "Security keys {list} are paired with each other.",
    ),
    (
        "모든 보안 키를 차례로 터치해 키별 값, 짝 기록, 키세트 비밀, 데이터 키를 모두 새로 만듭니다. 누군가 PIN을 알고 보안 키를 잠깐 가져가 터치했을 수 있을 때 쓰세요.\n등록한 키가 모두 여기 있어야 합니다. 다른 PC는 이 PC의 열쇠 확인 코드를 입력해야 받습니다. 비밀번호도 노출되었을 수 있으면 끝난 뒤 '비밀번호 변경'도 하세요. 계속할까요?",
        "Touch every security key in turn to renew each key's values, the pair records, the keyset secret and the data key. Use it when someone who knows a PIN may have borrowed a key and touched it.\nEvery registered key must be here. Other PCs take the result only with this PC's key check code. If the password may be exposed too, also use 'Change password' afterwards. Continue?",
    ),
    (
        "모든 보안 키를 하나씩 연결하고 터치하세요. ({i}/{n})",
        "Connect and touch every security key, one at a time. ({i}/{n})",
    ),
    (
        "마지막으로 보안 키 하나를 한 번 더 터치해 새 값을 확인합니다.",
        "Finally, touch one security key once more to check its new value.",
    ),
    (
        "이 Windows는 한 번의 터치로 두 값을 주지 않아 키마다 두 번 터치합니다.",
        "This Windows does not give two values in one touch, so each key is touched twice.",
    ),
    (
        "모든 보안 키를 새로 잠갔습니다. 다른 PC에서는 이 PC의 열쇠 확인 코드를 입력해야 받습니다.",
        "All security keys are re-locked. Other PCs take it only with this PC's key check code.",
    ),
    (
        "보안 키를 끄면 비밀번호와 열쇠 파일만으로 열리게 되어 더 약해집니다.\n데이터 키를 바꿉니다. 계속할까요?",
        "With security keys off, the vault opens with the password and key file alone, which is weaker.\nThe data key is changed. Continue?",
    ),
    (
        "보안 키를 껐습니다. 이제 비밀번호와 열쇠 파일만으로 열립니다.",
        "Security keys are off. The vault now opens with the password and key file alone.",
    ),
    (
        "다른 PC는 이 열쇠 파일을 USB로 받고 이 PC의 열쇠 확인 코드를 입력해야 합니다.",
        "Other PCs must take this key file by USB and enter this PC's key check code.",
    ),
    (
        "더 쓰지 않는 보안 키에서는 이 금고의 등록 '{display}'을(를) 지우세요.\n보안 키에서 등록 하나만 지우려면 키 제조사의 관리 도구를 쓰세요(YubiKey는 `ykman fido credentials delete`, Windows에서는 관리자 권한 명령 창에서). 이때 그 키의 PIN이 필요합니다. PIN이 없는 키는 먼저 PIN을 정해야 하는데, 그 키를 PIN 없이 쓰는 다른 고요 금고가 있으면 PIN을 정한 뒤 그 금고가 열리지 않을 수 있습니다.\n지우지 않으면 그 키와 예전 열쇠 파일 사본, 비밀번호로 예전 내용을 열 수 있습니다. 그 키를 다른 곳(다른 고요 금고, 웹사이트 패스키)에 쓰지 않을 때만 FIDO 초기화를 하세요. 초기화는 그 키의 모든 패스키와 다른 금고의 등록까지 지우며, 그 키가 다른 금고의 유일한 키라면 그 금고는 영영 열 수 없게 됩니다.",
        "On a security key you no longer use, delete this vault's registration '{display}'.\nTo delete one registration from a key, use the key maker's management tool (for a YubiKey `ykman fido credentials delete`, on Windows from an administrator command prompt). It needs the key's PIN. A key without a PIN needs one set first, and another Goyo vault that uses the key without a PIN may then no longer open.\nUntil it is deleted, that key with an old key file copy and the password opens the old contents. FIDO-reset the key only if it is used nowhere else (another Goyo vault, website passkeys): a reset deletes every passkey on the key and other vaults' registrations, and a vault whose only key it is can never be opened again.",
    ),
    (
        "모든 키와 짝을 맺은 키가 없습니다. 먼저 '짝 맺기'로 키를 모두 함께 터치하세요.",
        "No key is paired with all the others. First touch all keys together with 'Pair keys'.",
    ),
    (
        "다른 PC에서 보안 키가 제거되었습니다. 이 PC에서 고르기 전에는 무엇이 바뀌었는지 보여 주지 않습니다.\n잃어버렸거나 뺀 키를 모두 고르세요.",
        "Security keys were removed on another PC. Nothing about the change is shown before you choose on this PC.\nChoose every key that was lost or removed.",
    ),
    (
        "잃어버렸거나 뺀 키를 하나 이상 고르세요.",
        "Choose at least one key that was lost or removed.",
    ),
    (
        "다른 PC의 '열쇠 관리'에 지금 보이는 열쇠 확인 코드를 입력하세요(E{epoch} · XXXX-XXXX-XXXX-XXXX).\n이 PC에서는 코드를 입력하기 전에 무엇이 바뀌었는지 보여 주지 않습니다.",
        "Enter the key check code shown now in 'Key management' on the other PC (E{epoch} · XXXX-XXXX-XXXX-XXXX).\nNothing about the change is shown on this PC before the code is entered.",
    ),
    (
        "코드 형식이 맞지 않습니다. 16자리(예: E7 · 1A2B-3C4D-5E6F-7A8B)를 입력하세요.",
        "The code is not in the right form. Enter its 16 characters (for example E7 · 1A2B-3C4D-5E6F-7A8B).",
    ),
    ("코드로 확인…", "Confirm with a code…"),
    ("나중에", "Later"),
    (
        "바뀐 열쇠 파일을 확인했습니다. 이제 항목을 고치고 저장할 수 있습니다.",
        "The changed key file is confirmed. Entries can be edited and saved now.",
    ),
    (
        "바뀐 열쇠 파일을 확인하기 전에는 항목을 고치거나 저장하지 않습니다. '열쇠 관리'의 [받기…]로 확인하세요.",
        "Until the changed key file is confirmed, nothing is edited or saved. Confirm it with [Get…] in 'Key management'.",
    ),
    ("이 열쇠 파일 확인", "Confirm this key file"),
    (
        "이 PC는 이 열쇠 파일(수정 {e})을 아직 확인하지 않았습니다. 다른 PC의 '열쇠 관리'에 지금 보이는 열쇠 확인 코드를 입력하세요. 확인하기 전에는 항목을 고치거나 서버에 올리지 않습니다.",
        "This PC has not confirmed this key file (revision {e}) yet. Enter the key check code shown now in 'Key management' on another PC. Until then, nothing is edited or uploaded.",
    ),
    (
        "이 열쇠 파일은 보안 키 없이 열리지만, 이 금고에는 보안 키를 쓴 흔적이 있습니다. 다른 PC에서 보안 키를 끈 것이 맞을 때만, 그 PC의 열쇠 확인 코드를 입력하세요.",
        "This key file opens without a security key, but this vault shows signs of security keys. Enter the other PC's key check code only if security keys really were turned off there.",
    ),
    (
        "이 PC는 이 열쇠 파일을 아직 확인하지 않았습니다. 확인하기 전에는 항목을 고치거나 서버에 올리지 않습니다. 이 금고에는 보안 키를 쓴 흔적이 있는데, 이 열쇠 파일은 예전(0.8) 형식이라 열쇠 확인 코드로 확인할 수 없습니다.\r\n다른 PC에서 보안 키를 켰고 이 파일이 이 PC에서 쓰던 열쇠 파일이 맞을 때만 아래 '코드 없이 이 열쇠 파일 믿기…'를 누르고, 그다음 '열쇠 관리'에서 그 PC의 새 열쇠 파일을 받으세요(서버에 있으면 '서버의 새 열쇠 파일 받기…', 없으면 USB로 '새 열쇠 파일 받기').",
        "This PC has not confirmed this key file yet. Until then, no entry is edited and nothing is uploaded. This vault shows signs of security keys, but this key file has the old (0.8) format, which no key check code can confirm.\r\nOnly if security keys were turned on on another PC and this is the key file this PC has been using: press 'Trust this key file without a code…' below, then take that PC's new key file in 'Key management' ('Receive the new key file from the server…' when the server holds it, else by USB with 'Receive a new key file').",
    ),
    (
        "다른 PC의 코드가 다른 수정 번호(E…)로 시작하면, 이 열쇠 파일을 복사한 뒤 그 PC에서 열쇠를 다시 바꾼 것입니다. 그 PC의 지금 열쇠 파일을 다시 복사해 와서 여세요.",
        "If the other PC's code starts with another revision (E…), its keys changed again after this key file was copied. Copy that PC's current key file again and open it.",
    ),
    (
        "확인할 다른 PC가 없으면 이 열쇠 파일이 진짜인지 확인할 방법이 없습니다.\n잃어버린 보안 키와 그 PIN, 비밀번호를 가진 사람이 서버를 장악했다면 위조된 열쇠 파일일 수 있습니다(보안 키를 뺄 때 비밀번호도 바꿨다면 위조 파일은 새 비밀번호로 열리지 않습니다). 그래도 이 열쇠 파일을 믿고 쓸까요?",
        "Without another PC to check against, there is no way to tell whether this key file is genuine.\nIf someone with a lost security key, its PIN and the password took over the server, it may be forged (if the password was changed when the key was removed, a forged file does not open with the new password). Trust and use this key file anyway?",
    ),
    ("다른 PC의 열쇠 확인 코드 (예: E7 · 1A2B-3C4D-5E6F-7A8B)", "Another PC's key check code (e.g. E7 · 1A2B-3C4D-5E6F-7A8B)"),
    ("코드 확인", "Check code"),
    ("코드 없이 받기 (이 서버를 믿음)…", "Accept without a code (trust this server)…"),
    ("코드 없이 이 열쇠 파일 믿기…", "Trust this key file without a code…"),
    ("다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 위 칸에 입력한 뒤 '코드 확인'을 누르세요.", "Type the key check code shown under 'Key management' on another PC into the field above, then press 'Check code'."),
    ("잠그기", "Lock"),
    (
        "이 열쇠 파일을 확인했습니다. 이제 항목을 고치고 저장할 수 있습니다.",
        "This key file is confirmed. Entries can be edited and saved now.",
    ),
    (
        "보안 키는 8개까지 등록할 수 있습니다.",
        "Up to 8 security keys can be registered.",
    ),
    (
        "Windows 보안 창에서 보안 키를 연결하고 터치하세요… NFC 리더에 댈 키는 먼저 USB에서 뽑으세요.",
        "Connect and touch your security key in the Windows Security window… Unplug a key from USB before holding it to an NFC reader.",
    ),
    (
        "Windows 창에 이 보안 키를 쓸 수 없다고 나왔다면, 그 키는 이 열쇠 파일에 등록되지 않았거나 이 금고에서 뺀 키이거나 FIDO 초기화된 키입니다. 등록된 다른 보안 키로 하세요.",
        "If the Windows window said this security key cannot be used, the key is not registered in this key file, was removed from this vault or was FIDO-reset. Use another registered security key.",
    ),
    (
        "보안 키 확인을 취소했거나 시간이 지났습니다.",
        "The security key check was cancelled or timed out.",
    ),
    (
        "이 보안 키는 이미 이 금고에 등록되어 있습니다. 다른 키를 연결하세요.",
        "This security key is already registered for this vault. Connect another key.",
    ),
    (
        "이 보안 키에 등록할 자리가 다 찼을 수 있습니다. 쓰지 않는 등록(뺀 키, 실패한 등록, 쓰지 않는 웹사이트 패스키)을 키 제조사의 관리 도구로 지우거나 다른 키를 쓰세요.",
        "This security key may have no room left for another registration. Delete the registrations you no longer use (removed keys, failed registrations, unused website passkeys) with the key maker's management tool, or use another key.",
    ),
    (
        "이 보안 키는 hmac-secret(FIDO2 확장)을 지원하지 않습니다.",
        "This security key does not support hmac-secret (a FIDO2 extension).",
    ),
    (
        "이 보안 키는 PIN 필수 보호(credProtect)를 지원하지 않습니다. 다른 키를 쓰세요.",
        "This security key does not support required PIN protection (credProtect). Use another key.",
    ),
    (
        "Windows가 보안 키 요청을 거부했습니다(코드 0x80090027). 고요 금고를 다시 시작한 뒤 다시 하세요. 그래도 같으면 이 코드와 Windows 버전을 알려 주세요.",
        "Windows rejected the security key request (code 0x80090027). Restart Goyo Vault and try again. If it happens again, report this code and your Windows version.",
    ),
    (
        "USB·NFC 보안 키만 쓸 수 있습니다(Windows Hello·휴대폰 제외).",
        "Only USB and NFC security keys can be used (not Windows Hello or a phone).",
    ),
    (
        "클라우드로 동기화되는 패스키는 쓸 수 없습니다. USB·NFC 보안 키만 됩니다.",
        "Passkeys that sync through a cloud cannot be used. Only USB and NFC security keys work.",
    ),
    (
        "보안 키 응답이 올바르지 않습니다. 다른 키를 쓰거나 키를 확인하세요.",
        "The security key's answer is not valid. Use another key or check this one.",
    ),
    (
        "보안 키 응답을 확인할 수 없습니다.",
        "The security key's answer could not be verified.",
    ),
    (
        "이 보안 키는 이 열쇠 파일에 등록되어 있지 않습니다.",
        "This security key is not registered in this key file.",
    ),
    (
        "이 보안 키의 PIN 확인 여부가 등록 때와 다릅니다(키의 PIN 설정 변경 등). 키 설정을 되돌리거나, 다른 등록 키로 연 뒤 이 키를 빼고 다시 추가하세요.",
        "This security key's PIN check differs from when it was registered (its PIN setting changed, for example). Restore the key's setting, or open with another registered key, then remove this key and add it again.",
    ),
    (
        "이 보안 키가 같은 값을 다시 돌려주지 않아 저장하지 않았습니다.",
        "This security key did not return the same value again, so nothing was saved.",
    ),
    (
        "이 Windows에서는 보안 키(WebAuthn API 4 이상)를 쓸 수 없습니다. Windows를 업데이트하세요.",
        "Security keys (WebAuthn API 4 or later) cannot be used on this Windows. Update Windows.",
    ),
    (
        "보안 키 작업 실패 (코드 0x{hr:08X}).",
        "Security key operation failed (code 0x{hr:08X}).",
    ),
    (
        "보안 키 자체 시험에 실패했습니다.",
        "The security key self-test failed.",
    ),
    (
        "이 열쇠 파일은 보안 키가 필요합니다.",
        "This key file needs a security key.",
    ),
    (
        "보안 키 {N}은(는) 이 열쇠 파일에서 일시 정지되어 있습니다. 다른 보안 키로 연 뒤 '짝 맺기'로 이 키를 다시 쓰게 하세요.",
        "Security key {N} is suspended in this key file. Open with another security key, then use 'Pair keys' to let this key work again.",
    ),
    (
        "보안 키 {N}은(는) 이 열쇠 파일에서 일시 정지되었고 짝 기록이 없어 다시 쓸 수 없습니다. 다른 보안 키로 연 뒤 이 키를 빼고 다시 등록하세요.",
        "Security key {N} is suspended in this key file and has no pair record, so it cannot be used again. Open with another security key, then remove this key and register it again.",
    ),
    (
        "비밀번호가 맞다면 이 보안 키가 초기화되었거나 PIN 설정이 바뀌었을 수 있습니다. 다른 등록 키로 열어 보세요.",
        "If the password is right, this security key may have been reset or its PIN setting changed. Try another registered key.",
    ),
    (
        "보안 키 {list}은(는) 지금 터치한 키와 짝을 맺지 않아 새 열쇠 파일을 받을 수 없습니다. 그 키도 연결해 함께 터치하거나, 모든 키와 짝을 맺은 키로 하세요.",
        "Security key {list} is not paired with the key you touched, so it cannot get the new key file. Connect that key and touch it too, or use a key paired with every key.",
    ),
    (
        "이 보안 키의 응답이 이 열쇠 파일과 맞지 않습니다. 이 키를 빼고 나중에 다시 등록하세요.",
        "This security key's answer does not match this key file. Remove this key and register it again later.",
    ),
    (
        "보안 키 {list}에 새 열쇠를 전할 짝 기록이 열리지 않아 저장하지 않았습니다. 아무것도 바뀌지 않았습니다. '열쇠 관리'에서 짝 기록 상태를 확인한 뒤 다시 하세요.",
        "The pairing records that would give the new key to security key {list} did not open, so nothing was saved. Nothing changed. Check the pairing status in 'Key management', then try again.",
    ),
    (
        "이 변경은 망가진 짝 기록(보안 키 {o} → 보안 키 {t})을 고칩니다. 다른 PC가 이 수리를 받으려면 보안 키 {o}나 {t}가 승인해야 하는데, 두 키 모두 이번에 터치하지 않은 키에 닿지 않습니다. 먼저 보안 키 {o}, {t} 둘만 '짝 맺기'를 하거나, 빠진 키도 함께 터치하세요. 아무것도 바뀌지 않았습니다.",
        "This change repairs a broken pairing record (security key {o} → security key {t}). Other PCs take that repair only when key {o} or {t} approves it, but neither reaches the keys not touched this time. First pair keys {o} and {t} on their own, or touch the missing keys too. Nothing changed.",
    ),
    (
        "이 PC의 열쇠 기록(goyo-vault.keys)을 읽거나 쓸 수 없습니다. 보안 키 금고는 이 기록 없이 열쇠를 바꾸거나 받거나 서버에 올리지 않습니다. %LOCALAPPDATA%\\GoyoVault 폴더의 쓰기 권한을 확인하세요.",
        "This PC's key record (goyo-vault.keys) cannot be read or written. A security-key vault does not change, accept or upload keys without it. Check write access to the %LOCALAPPDATA%\\GoyoVault folder.",
    ),
    (
        "이 열쇠 변경은 지금 열쇠 파일과 맞지 않아 쓰지 않았습니다. 아무것도 바뀌지 않았습니다.",
        "This key change does not fit the key file as it is now, so nothing was written. Nothing changed.",
    ),
    (
        "뺀 보안 키가 다시 들어 있음",
        "a removed security key is back",
    ),
    (
        "제거된 보안 키가 승인함",
        "approved by a removed security key",
    ),
    ("보안 키 기록이 바뀜", "a security key's record changed"),
    ("짝 기록이 바뀜", "a pairing record changed"),
    ("짝 기록이 손상됨", "a pairing record is damaged"),
    ("설명되지 않는 변경", "an unexplained change"),
    (
        "이 열쇠 파일에는 이 PC에서 이미 뺀 보안 키가 들어 있거나, 그 키가 승인한 변경이 들어 있습니다. 예전 열쇠 파일로 되돌려졌거나 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC, 서버)을 쓰세요. 다른 PC의 열쇠 파일이라면 이 PC의 원래 열쇠 파일로 연 뒤 '새 열쇠 파일 받기'로 받으세요.",
        "This key file holds a security key that was already removed on this PC, or a change that key approved. It may have been put back from an old key file or forged, so it was not opened. Use the latest key file (a key backup, another PC, the server). If it is another PC's key file, open with this PC's own key file and take it with 'Receive a new key file'.",
    ),
    (
        "이 열쇠 파일의 보안 키 기록이 이 PC가 기록해 둔 것과 다릅니다. 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요.",
        "This key file's security key records differ from what this PC recorded. It may have been forged, so it was not opened. Use the latest key file (a key backup, another PC).",
    ),
    (
        "이 열쇠 파일의 OTP 설정이 이 PC가 기록해 둔 것과 다릅니다(설명되지 않는 변경). 위조되었을 수 있어 열지 않았습니다. 최신 열쇠 파일(열쇠 백업, 다른 PC)을 쓰세요.",
        "This key file's OTP setting differs from what this PC recorded (an unexplained change). It may have been forged, so it was not opened. Use the latest key file (a key backup, another PC).",
    ),
    (
        "고른 키가 받은 변경과 맞지 않아 받지 않았습니다. 이 변경은 이제 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력해야만 받을 수 있습니다. 키를 잃어버린 것이 확실하면 코드를 기다리지 말고 이 PC에서 '잃어버린 키 제거'를 하세요.",
        "The keys you picked do not match the change, so it was not taken. It can now be taken only by entering the key check code shown in 'Key management' on the other PC. If you are sure a key was lost, do not wait for the code: run 'Remove a lost key' on this PC.",
    ),
    (
        "고른 키가 바뀐 열쇠 파일과 맞지 않아 받지 않았습니다. 이 열쇠 파일은 이제 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력해야만 받을 수 있습니다. 그런 변경을 한 적이 없다면 이전 열쇠 파일(열쇠 백업)로 바꿔 놓으세요. 그때까지 이 PC는 항목을 고치거나 저장하거나 올리지 않습니다.",
        "The keys you picked do not match the changed key file, so it was not taken. It can now be taken only by entering the key check code shown in 'Key management' on the other PC. If no such change was made, put the previous key file (a key backup) back. Until then this PC does not edit, save or upload anything.",
    ),
    (
        "입력한 코드가 이 열쇠 파일과 맞지 않습니다. 다른 PC의 '열쇠 관리'에 지금 보이는 코드를 다시 확인하세요.",
        "The code you entered does not match this key file. Check the code shown now in 'Key management' on the other PC.",
    ),
    (
        "이 PC는 이 금고의 열쇠 파일을 아직 확인하지 않았습니다. 확인 전에는 다른 PC의 열쇠 확인 코드로 확인하는 새 버전만 받을 수 있습니다. 먼저 이 PC의 열쇠 파일을 코드로 확인하거나, 새 열쇠 파일로 복원하세요.",
        "This PC has not confirmed this vault's key file yet. Until it does, it takes only a newer version confirmed with the other PC's key check code. First confirm this PC's key file with the code, or restore with the new key file.",
    ),
    (
        "이 PC는 이 열쇠 파일을 아직 확인하지 않았습니다. 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력하기 전에는 항목을 고치거나 열쇠를 바꾸거나 서버에 올리지 않습니다.",
        "This PC has not confirmed this key file yet. Until you enter the key check code shown in 'Key management' on another PC, it does not edit entries, change keys or upload anything.",
    ),
    (
        "이 PC의 열쇠 파일이 바뀌었습니다. 잃어버린 키를 고르거나 다른 PC의 열쇠 확인 코드를 입력하기 전에는 항목을 고치거나 저장하거나 올리지 않습니다.",
        "This PC's key file changed. Until you pick the lost keys or enter the other PC's key check code, nothing is edited, saved or uploaded.",
    ),
    (
        "확인할 열쇠 파일이 없거나 그 사이에 바뀌었습니다. 처음부터 다시 하세요.",
        "There is no key file to confirm, or it changed meanwhile. Start again.",
    ),
    (
        "지난번 보안 키 {list} 제거가 저장 중에 끊겨 끝나지 않았습니다. 이 PC는 아직 보호되지 않습니다. [다시 하기]로 같은 내용으로 다시 하세요.",
        "The last removal of security key {list} was cut off while saving and did not finish. This PC is not protected yet. Use [Redo] to do it again with the same answers.",
    ),
    (
        "보안 키는 8개까지 등록할 수 있습니다. 두 열쇠 파일을 합치면 8개를 넘어 받지 않았습니다.",
        "Up to 8 security keys can be registered. Joining the two key files would give more than 8, so it was not taken.",
    ),
    // Stage 5c: the removals, the review, the adopt with keys.
    ("잃어버린 키 제거…", "Remove a lost key…"),
    ("키 빼기…", "Remove keys…"),
    ("잃어버린 키 제거", "Remove a lost key"),
    ("키 빼기", "Remove keys"),
    (
        "잃어버린 키를 모두 고르세요.",
        "Pick every key that was lost.",
    ),
    (
        "뺄 보안 키를 고르세요.",
        "Pick the security keys to remove.",
    ),
    (
        "같은 PIN을 쓰는 다른 보안 키를 고르세요. 그 키는 복제됐을 수 있다고 표시합니다.",
        "Pick the other security keys that use the same PIN. They are marked as possibly cloned.",
    ),
    (
        "대략 언제 잃어버렸나요? (모르면 비워 두세요)",
        "Roughly when was it lost? (Leave it empty if you do not know.)",
    ),
    ("비워 두면 모름", "Leave empty if unknown"),
    (
        "PIN이나 비밀번호를 다른 사람이 알 수 있나요? (보았거나, 키와 함께 적어 두었거나, 다른 곳에도 같은 것을 썼다면 '예')",
        "Could someone else know the PIN or the password? ('Yes' if someone saw it, it was written down with the key, or you use it elsewhere too)",
    ),
    ("예", "Yes"),
    ("아니요", "No"),
    ("모름", "Not sure"),
    (
        "비밀번호도 함께 바꾸기 (권장)",
        "Change the password too (recommended)",
    ),
    (
        "비밀번호도 바꾸면 잃어버린 키를 가진 사람이 만든 열쇠 파일은 새 비밀번호로 열리지 않습니다. 다른 PC에 이 변경 알림이 뜨지 않으면 서버가 숨기고 있을 수 있으니, 그 PC에서도 '잃어버린 키 제거'를 하세요.",
        "With a new password, a key file made by whoever has the lost key does not open with it. If another PC shows no notice of this change, the server may be hiding it: run 'Remove a lost key' on that PC too.",
    ),
    ("비밀번호도 바꾸기", "Change the password too"),
    (
        "비밀번호를 바꾸지 않으면, 잃어버린 키와 그 PIN, 비밀번호를 함께 가진 사람이 만든 열쇠 파일이 다른 PC에서 열릴 수 있습니다. 그래도 비밀번호를 바꾸지 않을까요?",
        "If you keep the password, a key file made by someone who has the lost key, its PIN and the password can open on other PCs. Keep the password anyway?",
    ),
    ("제거", "Remove"),
    ("빼기", "Remove"),
    (
        "날짜 형식이 맞지 않습니다. 예: 2026-10-29 (모르면 비워 두세요)",
        "The date is not in the right format. Example: 2026-10-29 (leave it empty if you do not know).",
    ),
    (
        "PIN이나 비밀번호를 다른 사람이 알 수 있는지 '예', '아니요', '모름' 중에서 고르세요.",
        "Choose 'Yes', 'No' or 'Not sure': could someone else know the PIN or the password?",
    ),
    (
        "잃어버린 키를 하나 이상 고르세요.",
        "Pick at least one lost key.",
    ),
    (
        "뺄 키를 하나 이상 고르세요.",
        "Pick at least one key to remove.",
    ),
    (
        "키를 모두 뺄 수는 없습니다. 하나 이상 남겨 두세요. 보안 키를 모두 없애려면 '보안 키 끄기'를 쓰세요.",
        "You cannot remove every key. Keep at least one. To remove all security keys, use 'Turn off keys'.",
    ),
    (
        "키를 고르면 어느 키를 터치할지 여기에 보여 줍니다.",
        "Pick keys, and this shows which key to touch.",
    ),
    (
        "터치할 키: 보안 키 {list} 중 하나",
        "Key to touch: one of security key {list}",
    ),
    (
        "일시 정지될 키: 보안 키 {list}",
        "Keys that would be suspended: security key {list}",
    ),
    (
        "이 키와만 짝을 맺은 키: 보안 키 {list} (함께 뺍니다)",
        "Keys paired only with these: security key {list} (removed too)",
    ),
    (
        "보안 키 {list}은(는) 빼는 키와만 짝을 맺었습니다. 남는 키로는 이 키에 새 열쇠를 줄 수 없고, 빼는 키가 몰래 넣은 키일 수도 있습니다. 남겨 두면 일시 정지되고 짝 기록이 남지 않아 다시 쓸 수 없습니다(빼고 다시 등록해야 합니다).\n다만 이 키가 다른 장소에서 쓰는 유일한 키일 수 있다면 남겨 두세요. 빼면 그 장소의 PC는 이 변경을 받을 때 다른 키를 가져가 짝을 맺은 뒤 '새 열쇠 파일 받기'로 합쳐야 합니다. 함께 뺄까요? (권장)",
        "Security key {list} is paired only with the keys being removed. No staying key can give it the new key, and it may be a key the removed one added in secret. If kept, it is suspended with no pair record left and cannot be used again (remove it and register it again).\nBut keep it if it may be the only key used at another site. If it is removed, that site's PC must take another key there and pair it, then join the files with 'Receive a new key file' when it takes this change. Remove it too? (Recommended)",
    ),
    (
        "보안 키 {list}은(는) 빼는 키와만 짝을 맺었습니다(예: 그 키로 추가한 예비 키). 이번에 함께 터치하면 그대로 남고, 터치하지 않으면 일시 정지되며 짝 기록이 남지 않아 나중에 빼고 다시 등록해야 합니다.\n이 키가 다른 장소에서 쓰는 유일한 키일 수 있다면, 먼저 '짝 맺기'로 남는 키와 짝을 맺은 뒤에 빼세요. 함께 빼려면 목록에서 고르세요.",
        "Security key {list} is paired only with the keys being removed (for example a spare added with one of them). Touched in this flow too, it stays as it is; untouched, it is suspended with no pair record left and must later be removed and registered again.\nIf it may be the only key used at another site, pair it with a staying key first ('Pair keys'), then remove the others. To remove it as well, pick it in the list.",
    ),
    (
        "보안 키 {list}은(는) 터치할 키와 짝을 맺지 않아 새 열쇠 파일을 받을 수 없습니다. 이대로 하면 이 키는 일시 정지되고, 나중에 '짝 맺기'로 다시 쓸 수 있습니다.",
        "Security key {list} is not paired with the key you touch, so it cannot receive the new key file. If you go on, it is suspended, and 'Pair keys' makes it usable again later.",
    ),
    (
        "모든 키와 짝을 맺은 키(보안 키 {full})로 터치하면 일시 정지되지 않습니다.",
        "Touching a key paired with every key (security key {full}) suspends none.",
    ),
    (
        "다음에 모든 키와 짝을 맺은 키(보안 키 {full})로 터치하면 일시 정지되지 않습니다.",
        "Next time, touching a key paired with every key (security key {full}) suspends none.",
    ),
    (
        "다만 보안 키 {orphans}은(는) 남는 짝 기록이 없어 다시 쓸 수 없고, 빼고 다시 등록해야 합니다.",
        "But security key {orphans} has no pair record left and cannot be used again: remove it and register it again.",
    ),
    (
        "그 키가 지금 여기 있으면 '그 키도 함께 터치'를 누르세요. 함께 터치한 키는 일시 정지되지 않습니다. 계속할까요?",
        "If that key is here now, press 'Touch that key too'. A key touched as well is not suspended. Go on?",
    ),
    ("계속", "Continue"),
    ("그 키도 함께 터치", "Touch that key too"),
    (
        "이 PC에서 처음 보는 키는 여기서 함께 터치할 수 없습니다. 계속할까요?",
        "A key new to this PC cannot be touched here as well. Continue?",
    ),
    (
        "함께 터치할 보안 키 {list}을(를) 연결하고 터치하세요.",
        "Connect security key {list}, to be touched as well, and touch it.",
    ),
    (
        "모든 키와 짝을 맺은 키가 없어, 보안 키 {list}도 연결해 함께 터치해야 합니다. 그 키가 지금 여기 없으면 '취소'를 누르고, 키가 모일 때 '짝 맺기'를 하세요.",
        "No key is paired with every other key, so security key {list} must be connected and touched as well. If it is not here now, press 'Cancel' and pair the keys when they are together.",
    ),
    (
        "보안 키 {x}과(와) {y} 사이의 짝 기록이 손상되어 있습니다. 두 키가 모두 여기 있으면 보안 키 {a}을(를) 터치한 뒤 다른 키도 함께 터치해, 이번 변경에서 고치세요. 한 키가 다른 곳에 있으면 '건너뛰기'를 누르세요. 변경은 그대로 진행됩니다.",
        "The pair record between security keys {x} and {y} is damaged. If both keys are here, touch security key {a}, then the other one as well, and this change repairs it. If one of them is elsewhere, press 'Skip': the change goes ahead as planned.",
    ),
    ("둘 다 터치", "Touch both"),
    (
        "이 금고의 기록을 무시하고, 이 열쇠 파일을 처음 보는 열쇠 파일로 확인합니다. 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 아래에 입력하세요.",
        "This vault's record is ignored, and this key file is checked as one seen for the first time. Enter below the key check code shown in 'Key management' on another PC.",
    ),
    ("건너뛰기", "Skip"),
    (
        "보안 키 {x}과(와) {y} 사이의 손상된 짝 기록은 고치지 않았습니다. 두 키를 한곳에서 '짝 맺기'하기 전까지 다른 PC가 이 변경을 받지 않을 수 있습니다.",
        "The damaged pair record between security keys {x} and {y} was not repaired. Until the two keys are paired at one site, other PCs may refuse this change.",
    ),
    (
        "선택한 보안 키 {list}을(를) 뺍니다. 남는 키 하나를 터치하면 새 키세트 비밀과 데이터 키를 만들고, 이 PC에서는 바로 끝납니다.\n다른 키를 옮길 필요는 없습니다. 뺀 키와 예전 비밀번호로는 앞으로 저장하는 내용을 열 수 없습니다. 계속할까요?",
        "This removes security key {list}. One touch of a staying key makes a new keyset secret and data key, and on this PC it is done at once.\nNo other key needs to travel. The removed keys and the old password cannot open what is saved from now on. Go on?",
    ),
    (
        "이 PC의 동기화가 멈춰 있지만, 잃어버린 키 제거는 이 PC를 바로 보호하므로 그대로 진행합니다. 다른 PC의 변경과는 나중에 합쳐집니다.",
        "This PC's sync is halted, but removing a lost key protects this PC at once, so it goes ahead. It is joined with the other PC's change later.",
    ),
    (
        "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다.\n이 금고를 쓰는 다른 PC마다 '잃어버린 키 제거'를 하거나, 그 PC를 열 때 보안 키 {list}을(를) 모두 고르세요(서버가 이 변경을 숨겨도 그 PC에서 직접 하면 바로 보호됩니다).",
        "Security key {list} is removed on this PC. This PC is protected from now on.\nOn every other PC that uses this vault, run 'Remove a lost key', or pick every security key {list} when it opens (done there, it protects that PC at once, even if the server hides this change).",
    ),
    (
        "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다.",
        "Security key {list} is removed on this PC. This PC is protected from now on.",
    ),
    (
        "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다. 다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다.\n다른 PC마다 둘 중 하나를 하세요. ① 이 열쇠 파일을 USB로 가져가 그 PC에서 '새 열쇠 파일 받기'로 받고, 보안 키 {list}을(를) 모두 고르세요(한 번 옮기면 끝납니다). ② 그 PC를 지금 바로 보호해야 하면 그 PC에서도 '잃어버린 키 제거'를 하세요. 그 뒤에는 두 PC가 서로의 열쇠 파일을 한 번씩 '새 열쇠 파일 받기'로 받아야 동기화가 다시 이어집니다.\n그 PC에서 쓰던 보안 키를 모두 뺐다면 그 PC는 열리지 않습니다. 여기서 새 키를 추가한 뒤, 그 키와 새 열쇠 파일을 함께 가져가 그 PC의 로그인에서 이 열쇠 파일을 고르고, 이 PC의 열쇠 확인 코드를 입력하세요.",
        "Security key {list} is removed on this PC. This PC is protected from now on. Other PCs halt sync until they take this key file.\nOn each other PC, do one of two things. ① Take this key file there on a USB stick, use 'Receive a new key file' and pick every security key {list} (one carry does it). ② If that PC must be protected right now, run 'Remove a lost key' there too; the two PCs must then each take the other's key file once with 'Receive a new key file' before sync goes on.\nIf every key that PC used was removed, it does not open: add a new key here, take that key and the new key file there together, choose this key file at that PC's login and enter this PC's key check code.",
    ),
    (
        "보안 키 {list}을(를) 이 PC에서 뺐습니다. 이 PC는 지금부터 보호됩니다. 다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다.",
        "Security key {list} is removed on this PC. This PC is protected from now on. Other PCs halt sync until they take this key file.",
    ),
    (
        "새 열쇠 파일은 보안 키 {present}(으)로만 열 수 있습니다(보안 키 {suspended}은(는) 일시 정지됨).\n그 키가 없는 다른 PC는 이 열쇠 파일을 받을 수 없으니, 그 PC마다 직접 같은 키를 빼세요(잃어버린 키는 '잃어버린 키 제거', 아니면 '키 빼기'). 두 PC의 열쇠 파일은 나중에 보안 키 하나를 다른 PC로 가져가 '새 열쇠 파일 받기'로 합칩니다.",
        "The new key file opens only with security key {present} (security key {suspended} is suspended).\nAnother PC without that key cannot take this key file, so remove the same keys on each such PC yourself ('Remove a lost key' for a lost key, otherwise 'Remove keys'). The two PCs' key files are joined later by taking one security key to the other PC and using 'Receive a new key file'.",
    ),
    (
        "같은 PIN을 쓰는 보안 키 {list}은(는) 복제됐을 수 있습니다. 모든 키가 한곳에 모일 때 '모든 키 새로 잠그기'를 하거나, 그 키를 빼고 다시 등록하세요.",
        "Security key {list}, which uses the same PIN, may have been cloned. When all keys are in one place, use 'Re-lock all keys', or remove that key and register it again.",
    ),
    (
        "보안 키 {list}을(를) 뺐습니다.",
        "Security key {list} is removed.",
    ),
    (
        "다른 PC는 이 열쇠 파일을 받을 때까지 동기화를 멈춥니다. 다른 PC에서 '새 열쇠 파일 받기'로 이 열쇠 파일을 받고, 뺀 보안 키 {list}을(를) 모두 고르세요.",
        "Other PCs halt sync until they take this key file. On each other PC, take it with 'Receive a new key file' and pick every removed security key {list}.",
    ),
    (
        "보안 키 {list} 제거를 저장하지 못했습니다. 아무것도 바뀌지 않았고 이 PC는 아직 보호되지 않습니다. 저장장치와 쓰기 권한을 확인한 뒤 다시 하세요.",
        "The removal of security key {list} could not be saved. Nothing changed, and this PC is not protected yet. Check the drive and the write permission, then try again.",
    ),
    ("다시 하기", "Redo"),
    (
        "'새 열쇠 파일 받기…'로 받으려던 열쇠 파일을 다시 고르세요. 이 PC의 키는 빼지 않습니다.",
        "Pick the key file you were receiving again with 'Receive a new key file…'. No key of this PC is removed.",
    ),
    ("동기화로 들어온 변경 확인", "Review what came in by sync"),
    (
        "보안 키를 잃어버린 날({date}) 하루 전부터 다른 PC에서 동기화로 들어온 변경입니다. 잃어버린 키를 가진 사람이 서버를 통해 바꿔 넣었을 수 있습니다.\n계좌번호, 지갑 주소, 복구 이메일, 로그인 주소처럼 바뀌면 위험한 항목을 확인하고 필요하면 고치세요. 확인을 마치면 '확인함'을 누르세요. 그 전에는 이 PC의 금고 내용을 서버에 올리지 않습니다.",
        "These are the changes that came in by sync from other PCs since the day before the security key was lost ({date}). Whoever has the lost key may have put them in through the server.\nCheck entries that are dangerous if changed, such as account numbers, wallet addresses, recovery e-mails and login addresses, and fix them if needed. When you are done, press 'Reviewed'. Until then this PC does not upload its vault.",
    ),
    (
        "보안 키를 잃어버린 날을 몰라, 이 PC에 동기화로 들어온 변경 기록 전체입니다. 잃어버린 키를 가진 사람이 서버를 통해 바꿔 넣었을 수 있습니다.\n계좌번호, 지갑 주소, 복구 이메일, 로그인 주소처럼 바뀌면 위험한 항목을 확인하고 필요하면 고치세요. 확인을 마치면 '확인함'을 누르세요. 그 전에는 이 PC의 금고 내용을 서버에 올리지 않습니다.",
        "The day the security key was lost is unknown, so this is every change that came in to this PC by sync. Whoever has the lost key may have put them in through the server.\nCheck entries that are dangerous if changed, such as account numbers, wallet addresses, recovery e-mails and login addresses, and fix them if needed. When you are done, press 'Reviewed'. Until then this PC does not upload its vault.",
    ),
    (
        "기록이 너무 많아 {time} 이전에 들어온 변경 일부는 이 목록에 없습니다. 백업이나 서버 기록과 비교하세요.",
        "There were too many records: some changes that came in before {time} are not in this list. Compare with a backup or the server history.",
    ),
    (
        "같은 항목에 다른 PC의 내용이 들어왔습니다: {title}. 이 PC의 원래 내용은 '{title2}' 항목으로 옮겨졌습니다. 어느 쪽이 맞는지 확인하고, 틀린 쪽을 고치거나 지우세요.",
        "Another PC's content came in under the same entry: {title}. This PC's original content moved to the entry '{title2}'. Check which one is right, and fix or delete the wrong one.",
    ),
    (
        "잃어버린 날 (비워 두면 기록 전체)",
        "Day of the loss (empty: all records)",
    ),
    (
        "항목을 두 번 누르면 열립니다. 날짜를 바꾸면 목록이 바뀝니다.",
        "Double-click an entry to open it. Changing the date changes the list.",
    ),
    ("확인함", "Reviewed"),
    ("고친 항목", "Edited entry"),
    (
        "다른 PC의 내용으로 바뀐 항목",
        "Entry with another PC's content",
    ),
    ("이 PC의 원래 내용", "This PC's original content"),
    (
        "다른 PC에서 지운 항목 (내용은 백업이나 서버 기록에서 확인)",
        "Entry deleted on another PC (see a backup or the server history for its content)",
    ),
    ("이 PC에 없는 항목", "Entry not on this PC"),
    (
        "이 PC에 없는 항목은 열 수 없습니다. 백업이나 서버 기록에서 확인하세요.",
        "An entry that is not on this PC cannot be opened. Check it in a backup or the server history.",
    ),
    ("검토를 마쳤습니다.", "Review done."),
    (
        "검토는 나중에 합니다. '확인함'을 누르기 전에는 이 PC의 금고 내용을 서버에 올리지 않고, 열 때마다 다시 보여 줍니다.",
        "Review later. Until you press 'Reviewed', this PC does not upload its vault, and the review comes back at every unlock.",
    ),
    (
        "열쇠 파일이 갈라졌습니다. [다른 PC 쪽 사용]은 이 PC의 열쇠 변경을 버리고 다른 PC의 열쇠 파일 내용으로 새 열쇠 파일을 씁니다(이 PC의 항목은 합칩니다).\n[둘 다 합치기]는 두 열쇠 파일을 합쳐 새로 만듭니다. 보안 키 구성이나 설정이 달라지는 쪽을 고르면, 먼저 잃어버린 키를 고르거나 다른 PC의 코드를 입력해야 합니다.",
        "The key files have split. [Use the other PC's] drops this PC's key changes and writes a new key file from the other PC's (this PC's entries are merged).\n[Join both] joins the two key files into a new one. If the side you choose changes the security keys or settings, you first pick the lost keys or enter the other PC's code.",
    ),
    ("열쇠 파일이 갈라졌습니다.", "The key files have split."),
    (
        "[다른 PC 쪽 사용]은 이 PC의 열쇠 변경을 버리고 다른 PC의 열쇠 파일 내용으로 새 열쇠 파일을 씁니다(이 PC의 항목은 합칩니다).",
        "[Use the other PC's] drops this PC's key changes and writes a new key file from the other PC's (this PC's entries are merged).",
    ),
    (
        "[둘 다 합치기]는 두 열쇠 파일을 합쳐 새로 만듭니다.",
        "[Join both] joins the two key files into a new one.",
    ),
    (
        "보안 키 구성이나 설정이 바뀌는 경우, 먼저 잃어버린 키를 고르거나 다른 PC의 코드를 입력해야 합니다.",
        "If it changes the security keys or settings, you first pick the lost keys or enter the other PC's code.",
    ),
    ("다른 PC 쪽 사용", "Use the other PC's"),
    ("둘 다 합치기", "Join both"),
    (
        "이 PC가 받은 변경은 다른 PC에서 제거한 보안 키 {n}이(가) 승인한 것입니다. '다른 PC 쪽 사용'을 권합니다.",
        "A change this PC holds was approved by security key {n}, which the other PC removed. 'Use the other PC's' is recommended.",
    ),
    ("뒤로", "Back"),
    (
        "이 PC가 다른 PC에서 받은 보안 키 {list} 제거를 되돌려, 그 키를 다시 쓸 수 있게 합니다.\n그 키를 잃어버렸거나 뺀 것이 맞다면 [아니요]를 누르고 [둘 다 합치기]를 쓰세요. 잘못 고른 키 때문에 받은 위조 변경을 되돌리는 경우에만 계속하세요.",
        "This undoes the removal of security key {list} that this PC took from another PC, so that key can be used again.\nIf that key really was lost or removed, press [No] and use [Join both]. Go on only to undo a forged change taken because of a wrong pick.",
    ),
    (
        "받으면 보안 키가 모두 빠지고 이 금고는 비밀번호와 열쇠 파일만으로 열리게 됩니다(더 약해집니다). 다른 PC에서 보안 키를 끈 것이 맞을 때만 받으세요.",
        "Taking it removes every security key, and this vault then opens with the password and key file alone (weaker). Take it only if security keys really were turned off on the other PC.",
    ),
    (
        "받을 열쇠 파일은 보안 키 {list}(으)로만 열 수 있습니다. 그 키가 지금 이 PC에 있으면 연결하고 '터치'를 누르세요. 없으면 '취소'를 누르세요.",
        "The key file to receive opens only with security key {list}. If that key is here now, connect it and press Touch. Otherwise press Cancel.",
    ),
    ("터치", "Touch"),
    (
        "받을 열쇠 파일에서 이 PC의 보안 키가 모두 빠졌거나 일시 정지되어 받을 수 없습니다. 키를 잃어버렸다면 이 PC에서 '잃어버린 키 제거'를 직접 하세요. 아니면 다른 키와 '짝 맺기'를 한 뒤 받으세요.",
        "Every security key of this PC is removed or suspended in the key file to receive, so it cannot be taken. If a key was lost, run 'Remove a lost key' on this PC yourself. Otherwise pair with another key first, then receive it.",
    ),
    (
        "받으면 일시 정지될 키: 보안 키 {list}",
        "Keys suspended if you take it: security key {list}",
    ),
    (
        "결과: 비밀번호만으로 열림",
        "Result: opens with the password alone",
    ),
    (
        "번호가 겹쳐 보안 키 {a}를 보안 키 {b}(으)로 바꿨습니다. 실물 키의 표시도 고치세요.",
        "The numbers collided: security key {a} is now security key {b}. Change the label on the physical key too.",
    ),
    (
        "PIN 없이 등록한 보안 키 {N}은(는) PIN을 쓰는 열쇠 파일에 넣을 수 없어 빠졌습니다. 다시 등록하세요.",
        "Security key {N}, registered without a PIN, cannot be in a key file that uses PINs, so it was left out. Register it again.",
    ),
    ("이 PC에서 처음 보는 키", "new to this PC"),
    (
        "이 열쇠 파일은 보안 키가 필요합니다(등록 {n}개). '잠금 해제'를 누르면 Windows 보안 창이 열립니다.",
        "This key file needs a security key ({n} registered). Unlock opens the Windows Security window.",
    ),
    (
        "보안 키 PIN은 Windows 창에 입력합니다.",
        "Enter the security key's PIN in the Windows window.",
    ),
    (
        "이 열쇠 파일은 보안 키 없이 비밀번호만으로 열립니다.",
        "This key file opens with the password alone, without a security key.",
    ),
    (
        "이 금고의 기록 지우고 다시 확인…",
        "Forget this vault's record and confirm again…",
    ),
    (
        "이 PC에 남은 이 금고의 열쇠 기록(수정 {old})을 지우고, 지금 고른 열쇠 파일을 처음 보는 열쇠 파일로 다시 확인합니다. 그 뒤에는 다른 PC의 '열쇠 관리'에 보이는 열쇠 확인 코드를 입력해야 항목을 고치거나 올릴 수 있습니다(다른 PC가 없으면 믿고 쓰기를 고를 수 있습니다).\n코드로 확인하기 전에 잠그면 이 기록은 지워지지 않고 그대로 남습니다. 이 PC에서 한 열쇠 변경 중 이 열쇠 파일에 없는 것은 사라질 수 있습니다. 다른 금고의 기록은 그대로 둡니다.\n예전 열쇠 파일이나 위조된 열쇠 파일일 수 있다면 누르지 마세요. 계속할까요?",
        "This forgets this PC's key record of this vault (revision {old}) and checks the chosen key file again as one it has never seen. Afterwards, entries can be edited or uploaded only once you enter the key check code shown in 'Key management' on another PC (with no other PC, you can choose to trust it).\nIf you lock before the code is confirmed, the record is not forgotten and stays as it is. Key changes made on this PC that this key file lacks may be lost. The records of other vaults stay.\nDo not press it if this may be an old or forged key file. Continue?",
    ),
    ("함께 빼기", "Remove them too"),
    ("남겨 두기", "Keep them"),
    (
        "오늘 이후 날짜는 쓸 수 없습니다. 날짜를 확인하세요(모르면 비워 두세요).",
        "A day after today cannot be used. Check the date (leave it empty if you do not know).",
    ),
    (
        "보안 키 {N}은(는) 이 열쇠 파일에서 일시 정지되어 있지만, 지금 연 보안 키 {M}과(와) 짝을 맺고 있어 이 PC에서 바로 다시 쓰게 할 수 있습니다.\n보안 키 {N}이(가) 이 PC 곁에 있다면 '열쇠 관리 › 짝 맺기'로 두 키를 터치하세요(2번 터치). 그러지 않으면 이 PC에서 쓸 수 있는 키가 보안 키 {M} 하나뿐일 수 있고, 그 키를 잃으면 다른 장소의 키를 가져올 때까지 이 PC에서 금고를 열 수 없습니다.",
        "Security key {N} is suspended in this key file, but it is paired with security key {M}, which you just opened with, so this PC can make it usable again at once.\nIf security key {N} is here, touch both keys with 'Key management › Pair keys' (2 touches). Otherwise security key {M} may be the only key this PC can use, and if it is lost, this PC cannot open the vault until a key from the other site is brought here.",
    ),
    (
        "보안 키 {N}은(는) 일시 정지되어 있어, 이 PC에서 쓸 수 있는 키가 보안 키 {M} 하나뿐일 수 있습니다. 두 키가 여기 있으면 '열쇠 관리 › 짝 맺기'로 다시 쓰게 하세요.",
        "Security key {N} is suspended, so security key {M} may be the only key this PC can use. If both keys are here, pair them in 'Key management › Pair keys'.",
    ),
    (
        "보안 키를 켰습니다. 보안 키 1개가 등록되었습니다.",
        "Security keys are on. One security key is registered.",
    ),
    (
        "열쇠 확인 코드: {code}. 다른 PC는 보안 키 추가나 설정 변경을 받을 때 이 코드를 입력하고, 제거를 받을 때는 잃어버린 키를 고릅니다. 모든 PC가 받아야 열쇠 변경이 끝난 것입니다.",
        "Key check code: {code}. Other PCs enter this code when they take a security key addition or a settings change, and pick the lost keys when they take a removal. The key change is finished once every PC has taken it.",
    ),
    ("열쇠 확인 코드:\n{code}\n\n다른 PC가 이 변경을 받을 때 이 코드가 필요합니다. 휴대폰으로 찍어 두세요. 이 코드는 '열쇠 관리'에도 계속 보입니다.", "Key check code:\n{code}\n\nOther PCs need this code to take this change. Take a photo of it with your phone. It also stays on the 'Key management' screen."),
    (
        "터치할 키: 보안 키 {list}",
        "Key to touch: security key {list}",
    ),
    (
        "새 금고를 만들었습니다. 보안 키 1개가 등록되었습니다. 아래 '열쇠 백업'으로 열쇠 파일 사본을 따로 두세요.",
        "New vault created. One security key is registered. Keep a copy of the key file elsewhere with 'Back up key' below.",
    ),
    (
        "일시 정지된 키: 보안 키 {list} ('짝 맺기'로 다시 쓰게 하세요)",
        "Suspended keys: security key {list} (make them usable again with 'Pair keys')",
    ),
    // Key-file sync (spec v3 §7.8-§7.19, stage 6).
    (
        "PIN 없이 등록한 보안 키 {list}을(를) 빼고 PIN으로 다시 등록하세요(보안 키를 끄고 PIN 사용으로 다시 켜기).",
        "Remove security key {list}, registered without a PIN, and register it again with a PIN (turn security keys off, then on again with PIN use).",
    ),
    (
        "열쇠 파일 동기화는 이 금고의 동기화를 켠 뒤에만 켤 수 있습니다.",
        "Key-file sync can be turned on only after sync is on for this vault.",
    ),
    (
        "이 Windows에서는 보안 키의 연결 방식을 확인할 수 없어 열쇠 파일 동기화를 켤 수 없습니다. Windows를 업데이트하세요.",
        "This Windows cannot tell how a security key is connected, so key-file sync cannot be turned on. Update Windows.",
    ),
    (
        "열쇠 파일 동기화를 지원하는 goyo-sync(보안 키 빌드)가 최근 10분 동안 응답하지 않았습니다. 그 goyo-sync를 실행한 뒤 다시 하세요.",
        "No goyo-sync with key-file sync (the security-key build) has answered in the last 10 minutes. Run that goyo-sync, then try again.",
    ),
    (
        "서버의 열쇠 파일 삭제가 끝난 뒤 다시 켜세요. (goyo-sync(보안 키 빌드)가 실행 중이어야 하고, 이 PC의 서버 연결이 이 금고의 열쇠 파일 요청을 받아야 합니다.)",
        "Turn it on again once the server has deleted the key file. (goyo-sync (the security-key build) must be running, and this PC's server connection must accept this vault's key-file requests.)",
    ),
    (
        "서버에 이미 이 금고의 열쇠 파일이 있습니다(다른 PC에서 켬). 그 파일을 받으세요.",
        "The server already has a key file of this vault (another PC turned it on). Take that file instead.",
    ),
    (
        "서버가 이 PC의 연결에서 이 금고의 열쇠 파일 동기화를 허용하지 않습니다. 서버 관리자가 이 PC의 강제 명령에 serve --key-sync=<금고 ID>를 넣어야 합니다.",
        "The server does not allow key-file sync for this vault on this PC's connection. The server administrator must add serve --key-sync=<vault ID> to this PC's forced command.",
    ),
    (
        "goyo-sync가 아직 서버의 열쇠 파일을 확인하지 않았습니다. 잠시 뒤 다시 하세요.",
        "goyo-sync has not checked the server's key file yet. Try again in a moment.",
    ),
    (
        "서버의 열쇠 파일 기록이 비정상적으로 큽니다. 서버 관리자가 data/<id>/k/를 지워야 합니다. 이 PC의 동기화 폴더가 바뀌었을 수도 있습니다(그 폴더의 incoming.goyokeysync를 지우면 goyo-sync가 다시 받습니다).",
        "The server's key-file record is abnormally large. The server administrator must delete data/<id>/k/. This PC's sync folder may also have been changed (delete incoming.goyokeysync in that folder and goyo-sync fetches it again).",
    ),
    (
        "동기화가 멈춰 있거나 받을 열쇠 파일이 기다리고 있어 열쇠 파일 동기화를 켤 수 없습니다. 먼저 그것을 해결하세요.",
        "Sync is halted or a key file waits to be taken, so key-file sync cannot be turned on. Resolve that first.",
    ),
    (
        "이 열쇠 파일은 열쇠 파일 동기화를 쓰지 않습니다.",
        "This key file does not use key-file sync.",
    ),
    (
        "서버에 이 금고의 열쇠 파일이 있어 다시 올릴 필요가 없습니다.",
        "The server has this vault's key file, so there is nothing to upload again.",
    ),
    ("사용자가 받지 않음", "not taken by the user"),
    (
        "받기 전에 확인할 열쇠 변경이 서버에 있습니다. 먼저 [받기…]로 잃어버린 키를 고르거나 코드를 입력하세요. 그 변경을 받지 않으려면 [받지 않기…]를 누르세요.",
        "A key change to confirm waits on the server. First pick the lost keys or enter the code with [Get…]. To not take that change, press [Don't take…].",
    ),
    (
        "먼저 서버의 새 열쇠 파일을 받으세요. 그래도 바꾸면 두 열쇠 파일이 갈라집니다.",
        "First take the server's new key file. If you change the keys anyway, the two key files fork.",
    ),
    (
        "서버에 받을 열쇠 파일이 없습니다.",
        "The server has no key file to take.",
    ),
    (
        "서버의 열쇠 파일은 이 PC가 받거나 합칠 수 있는 파일이 아닙니다. 다른 PC에서 바꾼 것이 맞다면 그 PC의 열쇠 파일을 USB로 가져와 '새 열쇠 파일 받기'로 받으세요.",
        "The server's key file is not one this PC can take or join. If another PC really changed it, bring that PC's key file by USB and take it with 'Receive a new key file'.",
    ),
    ("열쇠 파일: 이 PC에만 보관 (다른 PC에는 USB로)", "Key file: kept on this PC only (other PCs get it by USB)"),
    ("열쇠 파일: 서버로 동기화 (실험)", "Key file: synced through the server (experimental)"),
    ("열쇠 파일: 서버로 동기화 (실험) · 서버에 없음", "Key file: synced through the server (experimental) · not on the server"),
    (
        "서버에 새 열쇠 파일 있음 (수정 {e})",
        "A new key file is on the server (revision {e})",
    ),
    (
        "서버에 확인할 열쇠 변경 있음 (수정 {e})",
        "A key change to confirm is on the server (revision {e})",
    ),
    (
        "서버의 열쇠 파일과 갈라짐 (수정 {e}) · [받기…]로 합치세요",
        "Forked from the server's key file (revision {e}) · join them with [Get…]",
    ),
    (
        "확인을 기다리는 열쇠 변경(수정 {e})이 서버에 없습니다 · 받을 수 없으면 [받지 않기…]를 누르세요",
        "The key change waiting for confirmation (revision {e}) is no longer on the server · if it cannot be taken, press [Don't take…]",
    ),
    (
        "서버의 열쇠 파일 삭제: 대기 중 (goyo-sync가 처리합니다)",
        "Deleting the server's key file: waiting (goyo-sync handles it)",
    ),
    (
        "서버의 열쇠 파일 삭제: 대기 중 (goyo-sync가 서버를 확인하면, 이 PC가 잠금 해제되어 있을 때 요청합니다)",
        "Deleting the server's key file: waiting (once goyo-sync has checked the server, it is requested while this PC is unlocked)",
    ),
    (
        "서버의 열쇠 파일 삭제: 이 PC의 서버 연결이 이 금고의 열쇠 파일 요청을 받지 않습니다(--key-sync 목록에 없음). 다른 PC에서 이미 끄고 지웠다면 할 일이 없습니다.",
        "Deleting the server's key file: this PC's server connection does not accept this vault's key-file requests (not in the --key-sync list). If another PC already turned it off and deleted it, there is nothing to do.",
    ),
    (
        "서버의 열쇠 파일 삭제: 서버가 삭제했다고 응답함 (기록 {seq})",
        "Deleting the server's key file: the server answered that it deleted it (record {seq})",
    ),
    ("열쇠 파일 동기화 켜기…", "Turn key-file sync on…"),
    ("열쇠 파일 동기화 끄기…", "Turn key-file sync off…"),
    ("열쇠 파일 다시 올리기", "Upload the key file again"),
    ("받지 않기…", "Don't take…"),
    (
        "열쇠 파일 동기화를 켜면:\n1. 서버, 또는 동기화 SSH 키를 가진 사람이 열쇠 파일을 갖게 됩니다. 남는 장벽은 비밀번호와 보안 키(+PIN)뿐입니다.\n2. 올린 열쇠 파일은 그때 서버에 접근한 사람이 영원히 보관할 수 있습니다. 키 제거나 비밀번호 변경은 그 뒤에 저장하는 것만 보호합니다. 키를 잃었고 비밀번호가 알려졌을 수 있다면 비밀 자체를 바꾸세요.\n3. 해킹된 서버는 열쇠 변경을 어느 PC에 숨길 수 있습니다. 모든 PC가 받아야(잃어버린 키를 고르거나 코드를 입력해야) 열쇠 변경이 끝납니다. 키를 잃으면 모든 PC에서 '잃어버린 키 제거'를 하세요.\n4. 서버 사본은 백업이 아닙니다. USB 열쇠 백업과 2개 이상의 키가 여전히 필요하고, 복구 코드는 없습니다.\n5. PIN이 필수입니다: 6자 이상, 비밀번호와 다르게. 8번 틀리면 키가 잠기고, 초기화한 키로는 이 금고를 열 수 없습니다.\n6. 잃어버린 PC의 authorized_keys 줄은 바로 지우고, 사람마다 서버 계정을 따로 쓰세요.\n7. 휴대폰과 Windows Hello는 쓸 수 없고, USB나 NFC 보안 키만 씁니다.\n8. 더 쓰지 않는 키에서는 이 금고의 등록을 지우세요(제조사 도구, 예: 관리자 권한으로 ykman fido credentials delete; 키의 PIN 필요). FIDO 전체 초기화는 다른 곳에 쓰지 않는 키만 하세요.\n9. 열쇠 파일 사본이 각 PC의 동기화 폴더에 생깁니다.\n10. 열쇠를 바꾸면 다른 PC는 다음 잠금 해제 때 받습니다. 제거는 잃어버린 키를 고르고, 키 추가나 설정 변경은 바꾼 PC에 보이는 코드를 입력합니다. 보안 키를 끄면 열쇠 파일 동기화도 꺼지고, 다른 PC는 다시 USB로 열쇠 파일을 받아야 합니다.\n열쇠 파일 동기화를 켤까요?",
        "If you turn key-file sync on:\n1. The server, or anyone with a sync SSH key, gets the key file. The barriers left are the password and a security key (+PIN).\n2. Every uploaded key file can be kept for good by whoever had server access then. Removing a key or changing the password protects only what is saved later. If a key was lost and the password may be known, change the secrets themselves.\n3. A hacked server can hide a key change from a PC. A key change is finished only when every PC has taken it (by picking the lost keys or entering the code). If a key is lost, run 'Remove a lost key' on every PC.\n4. The server copy is not a backup. USB key backups and 2 or more keys are still needed, and there is no recovery code.\n5. The PIN is mandatory: 6+ characters, different from the password. 8 wrong tries lock the key, and a reset key can no longer open this vault.\n6. Remove a lost PC's authorized_keys line at once, and use one server account per person.\n7. Phones and Windows Hello cannot be used; only USB or NFC security keys.\n8. On a key you no longer use, delete this vault's registration (the vendor's tool, e.g. ykman fido credentials delete from an administrator prompt; it needs the key's PIN). Do a full FIDO reset only on a key used nowhere else.\n9. A key-file copy appears in each PC's sync folder.\n10. After a key change, the other PCs take it at their next unlock. A removal asks for the lost keys, an addition or a setting change for the code the changing PC shows. Turning security keys off turns key-file sync off, and the other PCs then need the key file by USB again.\nTurn key-file sync on?",
    ),
    (
        "서버에 이 금고의 열쇠 파일이 없습니다. 다른 PC에서 열쇠 파일 동기화를 끈 것이라면 다시 올리지 말고 그 PC의 열쇠 파일을 USB로 받으세요. 아무도 끄지 않았는데 지워진 것이 확실할 때만 다시 올리세요.\n이 PC의 열쇠 파일을 다시 올릴까요?",
        "The server has no key file of this vault. If another PC turned key-file sync off, do not upload again: take that PC's key file by USB. Upload again only if you are sure it was deleted while nobody turned it off.\nUpload this PC's key file again?",
    ),
    (
        "열쇠 파일 동기화를 켰습니다. goyo-sync가 서버에 열쇠 파일을 올립니다. 다른 PC는 다음 잠금 해제 때 이 PC의 열쇠 확인 코드를 입력해야 받습니다.",
        "Key-file sync is on. goyo-sync uploads the key file to the server. The other PCs must enter this PC's key check code at their next unlock to take it.",
    ),
    (
        "열쇠 파일을 다시 올리도록 했습니다. goyo-sync가 서버에 올립니다.",
        "The key file is set to upload again. goyo-sync uploads it to the server.",
    ),
    (
        "열쇠 파일 동기화를 끕니다. 서버에 열쇠 파일 삭제를 요청하고 데이터 키를 바꿉니다. 다른 PC는 동기화를 멈추고 이 열쇠 파일을 USB로 받아야 합니다. 계속할까요?",
        "This turns key-file sync off. It asks the server to delete the key file and changes the data key. The other PCs halt sync and must take this key file by USB. Continue?",
    ),
    (
        "이 열쇠 파일은 열쇠 파일 동기화를 씁니다. 보안 키를 끄면 열쇠 파일 동기화도 끄고, 서버에 열쇠 파일 삭제를 요청합니다. 다른 PC는 동기화를 멈추고 이 열쇠 파일을 USB로 받아야 합니다.",
        "This key file uses key-file sync. Turning security keys off also turns key-file sync off and asks the server to delete the key file. The other PCs halt sync and must take this key file by USB.",
    ),
    (
        "서버에 이 PC가 받지 않은 열쇠 파일(수정 {e})이 있습니다. 다른 PC의 변경일 수도, 위조된 파일일 수도 있습니다. 끄면 그 파일도 서버에서 지워지고, 다른 PC의 변경이라면 그 PC의 변경은 USB로 옮겨야 합니다. 끄기는 그래도 데이터 키를 바꾸므로, 앞으로 저장하는 항목은 서버에 남았던 열쇠 파일로 열리지 않습니다.",
        "The server has a key file this PC has not taken (revision {e}). It may be another PC's change, or a forged file. Turning off deletes that file from the server too, and if it is another PC's change, that change must be carried by USB. Turning off still changes the data key, so entries saved from now on do not open with the key file that was on the server.",
    ),
    (
        "열쇠 파일 동기화를 지원하는 goyo-sync(보안 키 빌드)가 응답하지 않습니다. 끄기는 지금 하지만, 서버의 열쇠 파일은 그 goyo-sync가 실행될 때까지 지워지지 않습니다. 계속할까요?",
        "No goyo-sync with key-file sync (the security-key build) answers. Turning off happens now, but the server's key file is not deleted until that goyo-sync runs. Continue?",
    ),
    (
        "이 PC에 서버 확인 기록이 없어, goyo-sync가 서버를 확인한 뒤 이 PC를 한 번 더 잠금 해제해야 삭제 요청이 나갑니다.",
        "This PC has no record of the server, so the deletion is requested only after goyo-sync has checked the server and this PC is unlocked once more.",
    ),
    (
        "이 PC의 서버 연결이 이 금고의 열쇠 파일 요청을 받지 않아(서버 강제 명령에 --key-sync=<금고 ID> 없음) 서버의 열쇠 파일을 지울 수 없습니다.
열쇠 파일 동기화를 쓰던 금고에서 서버가 이렇게 답한다면 서버 설정이 바뀌었거나 서버가 해킹되었을 수 있습니다. 끄기는 그래도 데이터 키를 바꾸므로, 앞으로 저장하는 항목은 서버에 남은 열쇠 파일로 열리지 않습니다. 다만 서버 관리자가 이 PC의 줄에 그 설정을 넣거나 data/<id>/k/를 지울 때까지 이 PC의 금고는 서버에 올라가지 않습니다(서버의 열쇠 파일이 다른 상태를 요구합니다). 끌까요?",
        "This PC's server connection does not accept this vault's key-file requests (no --key-sync=<vault ID> in the server's forced command), so the server's key file cannot be deleted.
If the server answers this way for a vault that used key-file sync, the server settings changed or the server may be hacked. Turning off still changes the data key, so entries saved from now on do not open with the key file left on the server. But until the server administrator adds that setting to this PC's line or deletes data/<id>/k/, this PC's vault is not uploaded (the server's key file asks for another state). Turn it off?",
    ),
    ("열쇠 파일 동기화를 껐습니다.", "Key-file sync is off."),
    (
        "서버에 열쇠 파일 삭제를 요청했습니다(해킹된 서버라면 이미 복사했을 수 있습니다).",
        "The server was asked to delete the key file (a hacked server may already have copied it).",
    ),
    (
        "goyo-sync가 서버를 확인하면 열쇠 파일 삭제를 요청합니다(이 PC를 잠금 해제한 상태에서).",
        "Once goyo-sync has checked the server, the key file's deletion is requested (while this PC is unlocked).",
    ),
    (
        "서버에는 지울 열쇠 파일이 없습니다(이미 다른 PC에서 껐거나 지워졌습니다).",
        "The server has no key file to delete (another PC already turned it off, or it was deleted).",
    ),
    (
        "다른 PC는 동기화를 멈추니 이 열쇠 파일을 USB로 옮겨 '새 열쇠 파일 받기'를 하세요. 더 쓰지 않는 보안 키는 그 키에서 이 금고의 등록을 지우세요(다른 곳에 쓰지 않는 키만 FIDO 초기화).",
        "The other PCs halt sync: carry this key file by USB and run 'Receive a new key file' there. On a security key you no longer use, delete this vault's registration on that key (a FIDO reset only for a key used nowhere else).",
    ),
    (
        "열쇠 파일 동기화를 끄지 못했습니다. 아무것도 바뀌지 않았습니다.",
        "Key-file sync could not be turned off. Nothing changed.",
    ),
    (
        "받은 결과는 열쇠 파일 동기화가 꺼진 열쇠 파일입니다.",
        "The result is a key file with key-file sync off.",
    ),
    (
        "서버의 열쇠 파일을 지우도록 요청합니다(해킹된 서버라면 이미 복사했을 수 있습니다).",
        "It asks the server to delete its key file (a hacked server may already have copied it).",
    ),
    (
        "서버의 열쇠 파일은 지우지 않습니다. 이미 다른 PC에서 끄고 지웠거나, 서버에 있는 것은 다른 PC가 나중에 정한 설정입니다(이 PC가 전에 쓰던 열쇠 파일이 서버에 남아 있으면 goyo-sync가 서버를 확인한 뒤 지우도록 요청합니다).",
        "It does not delete the server's key file. Another PC already turned it off and deleted it, or the one on the server is a setting another PC chose later (if a key file this PC used before is still on the server, its deletion is requested once goyo-sync has checked the server).",
    ),
    (
        "다른 PC는 이 열쇠 파일을 USB로 받아야 합니다.",
        "The other PCs must take this key file by USB.",
    ),
    (
        "이 열쇠 변경을 받지 않습니다. 다른 PC에서 실제로 바꾼 것이라면 이 PC는 동기화를 계속 멈춘 채로 남습니다(나중에 USB로 받을 수 있습니다). 위조된 것이 확실할 때만 누르세요. 그 PC를 더 쓸 수 없어서라면 받지 않기 대신 '다른 PC가 없어 이 PC 상태로 올리기'(그 버튼이 있을 때)나 '열쇠 파일 동기화 끄기'를 하세요.",
        "This change is not taken. If another PC really made it, this PC stays halted (you can take it by USB later). Press this only if you are sure it is forged. If it is because that PC can no longer be used, use 'Upload this PC's state, no other PC' (when that button is shown) or 'Turn key-file sync off' instead.",
    ),
    (
        "이 열쇠 변경을 받지 않았습니다. 서버에 다른 열쇠 파일이 올 때까지 동기화를 멈춥니다.",
        "This key change was not taken. Sync stays halted until another key file arrives on the server.",
    ),
    (
        "서버에 이 변경 전 금고 기록(최근 200개)이 남아 있습니다. 빠진 키와 예전 비밀번호를 가진 사람은 그 기록을 열 수 있습니다. 지울까요? 지우면 그 기록으로 되돌릴 수 없고, 해킹된 서버라면 이미 복사해 두었을 수 있습니다. 잃어버린 키와 비밀번호가 함께 노출되었을 수 있다면 금고 안의 비밀 자체를 바꾸세요.",
        "The server still has the vault versions from before this change (the last 200). Someone with the removed key and the old password can open them. Delete them? Then you cannot go back to them, and a hacked server may already have copied them. If the lost key and the password may both be exposed, change the secrets in the vault themselves.",
    ),
    (
        "서버에 이 변경 전 금고 기록을 지우도록 요청했습니다(goyo-sync가 보냅니다).",
        "The server was asked to delete the vault versions from before this change (goyo-sync sends it).",
    ),
    (
        "서버가 이 금고에서 이미 본 것보다 오래된 열쇠 파일을 보냈습니다. 받지 않았습니다.",
        "The server sent an older key file than one this PC already saw for this vault. It was not taken.",
    ),
    (
        "서버의 열쇠 파일을 받지 않고 동기화를 멈췄습니다({reason}). 다른 PC에서 바꾼 것이 맞다면 그 PC의 열쇠 파일을 USB로 가져와 '새 열쇠 파일 받기'로 받으세요. 그런 일이 없었다면 서버가 위조했을 수 있습니다.",
        "The server's key file was not taken and sync halted ({reason}). If another PC really changed it, bring that PC's key file by USB and take it with 'Receive a new key file'. If not, the server may have forged it.",
    ),
    (
        "받아 둔 서버 열쇠 파일을 읽을 수 없습니다. 무시했습니다.",
        "The server key file received cannot be read. It was ignored.",
    ),
    (
        "다른 PC에서 보안 키 구성이나 설정을 바꾼 열쇠 파일이 서버에 있습니다. 받기 전에 잃어버린 키를 고르거나 다른 PC의 열쇠 확인 코드를 입력해야 합니다('열쇠 관리'의 [받기…]). 그때까지 이 PC는 서버에 아무것도 올리지 않고 받은 사본도 합치지 않습니다. 키를 잃어버렸다면 '잃어버린 키 제거'를 이 PC에서도 하세요.",
        "A key file in which another PC changed the security keys or a setting is on the server. Before taking it, pick the lost keys or enter the other PC's key check code ([Get…] in 'Key management'). Until then this PC uploads nothing to the server and merges no copy it receives. If a key was lost, run 'Remove a lost key' on this PC too.",
    ),
    (
        "서버에 이 금고의 열쇠 파일이 없습니다(다른 PC에서 열쇠 파일 동기화를 껐거나 서버에서 지움). 다른 PC에서 끈 것이라면 다시 올리지 말고 그 PC의 열쇠 파일을 USB로 받으세요. 아무도 끄지 않았는데 지워진 것이 확실할 때만 '열쇠 관리'에서 '열쇠 파일 다시 올리기'를 누르세요. 그때까지 이 PC는 서버 사본을 합치지도 올리지도 않습니다(변경은 이 PC에 저장됩니다).",
        "The server has no key file of this vault (another PC turned key-file sync off, or it was deleted on the server). If another PC turned it off, do not upload again: take that PC's key file by USB. Press 'Upload the key file again' in 'Key management' only if you are sure it was deleted while nobody turned it off. Until then this PC neither merges nor uploads server copies (changes are saved on this PC).",
    ),
    (
        "다른 PC에서 바꾼 열쇠 파일(수정 {e})이 서버에 있습니다. '열쇠 관리'에서 [받기…]를 누르세요.",
        "A key file changed on another PC (revision {e}) is on the server. Press [Get…] in 'Key management'.",
    ),
    ("서버가 이 금고의 열쇠 파일 동기화를 받지 않습니다: 서버 authorized_keys의 이 PC 줄(강제 명령)에 --key-sync=<금고 ID>가 없습니다. goyo-sync 설정의 '강제 명령 줄…'이 만든 줄로 바꾸면 goyo-sync가 2분 안에 다시 확인합니다.", "The server does not take key-file sync for this vault: this PC's line in the server's authorized_keys (the forced command) lacks --key-sync=<vault ID>. Replace it with the line goyo-sync's 'Forced command line…' makes, and goyo-sync checks again within two minutes."),
    (
        "goyo-sync나 서버가 이 PC의 열쇠 파일을 받지 않았습니다(형식 또는 크기). 그동안 이 PC의 금고는 서버에 올라가지 않습니다. goyo-sync와 서버 스크립트를 같은 버전으로 업데이트하세요. 업데이트한 뒤 goyo-sync가 다시 시작되거나 '지금 동기화'를 누르면 다시 올립니다.",
        "goyo-sync or the server did not accept this PC's key file (format or size). Meanwhile this PC's vault is not uploaded. Update goyo-sync and the server script to the same version. After the update, it is uploaded again when goyo-sync restarts or you press 'Sync now'.",
    ),
    (
        "이 금고는 열쇠 파일 동기화를 쓰지만, 최근 10분 동안 열쇠 파일 동기화를 지원하는 goyo-sync(보안 키 빌드)의 응답이 없습니다. 그 goyo-sync를 실행하세요. 그 전에는 열쇠 파일이 오가지 않고, 끈 경우 서버의 열쇠 파일도 지워지지 않습니다.",
        "This vault uses key-file sync, but no goyo-sync with key-file sync (the security-key build) has answered in the last 10 minutes. Run that goyo-sync. Until then no key file moves, and after turning off the server's key file is not deleted either.",
    ),
    (
        "열쇠 파일 동기화를 다시 켜지 않을 거라면, 모든 PC가 이 끄기를 받은 뒤(이 열쇠 파일을 USB로 받거나 그 PC에서 직접 끔) 서버 관리자에게 모든 PC의 강제 명령에서 이 금고 ID를 --key-sync 목록에서 빼 달라고 하세요. 빼지 않으면 그 줄의 동기화 키를 훔친 사람이 이 금고의 업로드를 막을 수 있습니다.",
        "If you will not turn key-file sync on again: once every PC has taken this off (taken this key file by USB, or turned it off itself), ask the server administrator to remove this vault ID from the --key-sync list in every PC's forced command. Otherwise someone who steals that line's sync key can block this vault's uploads.",
    ),
    (
        "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라졌습니다. 동기화를 멈췄습니다. 한 PC에서 '열쇠 관리 › 새 열쇠 파일 받기'로 다른 PC의 열쇠 파일을 받으세요. 보안 키 구성이 다르면 잃어버린 키를 고르거나 다른 PC의 열쇠 확인 코드를 입력해야 합니다. 키를 잃어버렸다면 이 PC에서도 '잃어버린 키 제거'를 하세요. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.",
        "Two PCs changed the keys apart, so the key files forked. Sync halted. On one PC, take the other PC's key file with 'Key management › Receive a new key file'. If the security keys differ, you must pick the lost keys or enter the other PC's key check code. If a key was lost, run 'Remove a lost key' on this PC too. If nothing like that happened, the server copy may be forged.",
    ),
    (
        "정리 요청을 쓰지 못했습니다. 동기화 폴더를 확인하세요.",
        "The prune request could not be written. Check the sync folder.",
    ),
    // Completion, part 2 (spec §7.15a, §7.18, §5.8).
    (
        "서버의 최신 금고 사본(수정 {epoch}, 열쇠 {key})이 다시 올리려는 열쇠 파일과 맞지 않아 아무것도 하지 않았습니다. 그 사본을 쓴 PC를 더 쓸 수 없는 것이 확실할 때만 먼저 '서버 사본을 이 PC 상태로 덮어쓰기…'를 하고 다시 하세요.",
        "The server's latest vault copy (revision {epoch}, key {key}) does not match the key file to upload again, so nothing was done. Only if you are sure the PC that wrote that copy can no longer be used, first use 'Overwrite the server copy with this PC's state…', then try again.",
    ),
    (
        "서버의 열쇠 파일은 이제 이 PC 상태로 다시 올려 대신할 수 있는 변경이 아닙니다. '열쇠 관리'를 다시 확인하세요.",
        "The server's key file is no longer a change this PC's state can be uploaded over. Check 'Key management' again.",
    ),
    (
        "위조된 연결",
        "a forged link",
    ),
    (
        "다른 PC가 없어 이 PC 상태로 올리기…",
        "Upload this PC's state, no other PC…",
    ),
    (
        "서버의 새 열쇠 파일(다른 PC에서 바꾼 것)을 받지 않고, 이 PC의 열쇠 파일을 그보다 높은 수정 번호로 다시 올립니다. 그 PC를 더 쓸 수 없고 그 변경을 받은 PC가 하나도 없을 때만 하세요. 그 변경(예: 그 PC에서 추가한 보안 키)은 사라지니 필요하면 다시 하세요.",
        "The server's new key file (changed on another PC) is not taken; this PC's key file is uploaded again at a higher revision. Do this only if that PC can no longer be used and no PC has taken that change. The change (for example a security key added on that PC) is lost, so make it again if needed.",
    ),
    (
        "이 PC는 지금 열쇠 파일을 이 PC에만 두고 있습니다. 다시 올리면 이 PC에서도 열쇠 파일 동기화가 켜집니다. 원하지 않으면 끝난 뒤 '열쇠 파일 동기화 끄기'를 하세요(데이터 키를 바꿉니다).",
        "This PC keeps its key file on this PC only. Uploading it again turns key-file sync on here too. If you do not want that, use 'Turn key-file sync off' afterwards (it changes the data key).",
    ),
    (
        "다른 PC의 변경을 받지 않고 이 PC의 열쇠 파일을 다시 올렸습니다.",
        "The other PC's change was not taken; this PC's key file was uploaded again.",
    ),
    (
        "다른 PC들이 아직 이 제거를 받지 않았을 수 있습니다. 각 PC는 열 때 이 PC에서 뺀 보안 키를 모두 고르거나, 뺀 키를 모르는 PC라면 이 PC의 열쇠 확인 코드 {code}를 입력해 받습니다. 응답이 없는 PC는 서버가 이 변경을 숨기고 있을 수 있으니 그 PC에서 '잃어버린 키 제거'를 하세요. 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.",
        "Other PCs may not have taken this removal yet. Each takes it when opened by picking every security key removed here, or, on a PC that never knew a removed key, by typing this PC's key check code {code}. On a PC that does not respond, the server may be hiding this change: run 'Remove a lost key' there. When all are done, press [All PCs confirmed].",
    ),
    (
        "다른 PC들이 아직 이 열쇠 변경을 받지 않았을 수 있습니다. 각 PC는 다음 잠금 해제 때 받고, 열쇠 파일을 그 PC에만 두던 PC는 이 PC의 열쇠 확인 코드 {code}를 입력합니다. 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.",
        "Other PCs may not have taken this key change yet. Each takes it at its next unlock; a PC that kept its key file to itself types this PC's key check code {code}. When all are done, press [All PCs confirmed].",
    ),
    (
        "다른 PC들이 아직 이 열쇠 변경을 받지 않았을 수 있습니다. 각 PC는 열 때 이 PC의 열쇠 확인 코드 {code}를 입력해 받습니다. 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.",
        "Other PCs may not have taken this key change yet. Each takes it when opened, by typing this PC's key check code {code}. When all are done, press [All PCs confirmed].",
    ),
    (
        "다른 PC들이 아직 이 열쇠 변경을 받지 않았을 수 있습니다. 각 PC는 다음 잠금 해제 때 받습니다(비밀번호를 바꿨다면 새 비밀번호로 여세요). 모두 마쳤으면 [모든 PC 확인 완료]를 누르세요.",
        "Other PCs may not have taken this key change yet. Each takes it at its next unlock (after a password change, open with the new password). When all are done, press [All PCs confirmed].",
    ),
    (
        "다른 PC들이 이 제거를 받았는지 확인 전입니다. 받지 못하는 PC에서는 '잃어버린 키 제거'를 하세요.",
        "Not yet confirmed that the other PCs took this removal. On a PC that never gets it, run 'Remove a lost key'.",
    ),
    (
        "다른 PC들이 이 열쇠 변경을 받았는지 확인 전입니다. 할 일은 '열쇠 관리'에 있습니다.",
        "Not yet confirmed that the other PCs took this key change. See 'Key management'.",
    ),
    (
        "모든 PC 확인 완료",
        "All PCs confirmed",
    ),
    (
        "다른 PC들이 이 변경을 받았는지 확인 전",
        "Not yet confirmed that the other PCs took this change",
    ),
    (
        "모든 PC가 이 열쇠 변경을 받은 것으로 기록했습니다.",
        "Recorded that every PC took this key change.",
    ),
    (
        "두 PC에서 따로 한 보안 키 제거를 합쳤습니다. 열쇠 확인 코드 {code}",
        "Merged the key removals made apart on two PCs. Key check code {code}",
    ),
    (
        "두 PC에서 따로 한 보안 키 제거라면 다음 잠금 해제 때 이 PC의 보안 키와 비밀번호로 열어 합칩니다. 열리지 않으면 합치지 않고 알립니다. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.",
        "If two PCs each removed a security key apart, the next unlock opens the other file with this PC's security key and password and merges them. If it does not open, nothing is merged and you are told. If nothing like that happened, the server copy may be forged.",
    ),
    (
        "두 PC에서 따로 열쇠를 바꿔 열쇠 파일이 갈라졌습니다. 동기화를 멈췄습니다. 두 PC에서 따로 보안 키를 제거한 것이라면 '열쇠 관리'의 [받기…]로 합칠 수 있습니다(다른 보안 키나 다른 비밀번호가 필요합니다). 다른 변경이라면 한 PC에서 '새 열쇠 파일 받기'로 받으세요. 그런 일이 없었다면 서버 사본이 위조되었을 수 있습니다.",
        "Two PCs changed the keys apart, so the key files forked. Sync halted. If two PCs each removed a security key apart, they can be merged with [Get…] in 'Key management' (another security key or another password is needed). For any other change, take the other PC's key file on one PC with 'Receive a new key file'. If nothing like that happened, the server copy may be forged.",
    ),
    // goyo-sync's forced-command line (spec §7.12).
    (
        "고급 설정의 스크립트 경로나 파이썬 명령에 쓸 수 없는 글자가 있어 강제 명령 줄을 만들지 않았습니다. 그 두 칸을 고친 뒤 다시 누르세요.",
        "The script path or the Python command in Advanced settings has characters that cannot go in the forced command line, so no line was made. Fix those two fields and press it again.",
    ),
    (
        "강제 명령 줄…",
        "Forced command line…",
    ),
    (
        "열쇠 파일 동기화(실험)는 고요 금고의 '열쇠 관리'에서 켭니다. 켠 금고는 서버에 있는 이 PC의 줄에도 있어야 합니다.",
        "Key-file sync (experimental) is turned on in Goyo Vault's 'Key management'. A vault with it on must also be in this PC's line on the server.",
    ),
    (
        "restrict,command=\"{}\" <이 PC 전용 키의 공개 키> goyo-sync",
        "restrict,command=\"{}\" <public key of this PC's dedicated key> goyo-sync",
    ),
    (
        "목록에 열쇠 파일 동기화를 쓰는 금고가 없어 --key-sync가 없는 줄입니다.\n· 새 PC라면: 먼저 '이 PC로 가져오기…'로 금고를 가져온 뒤 이 버튼을 다시 누르세요. 다른 PC에서 열쇠 파일 동기화를 켠 금고는 그때 줄에 들어갑니다.\n· 이 PC의 금고라면: 고요 금고의 '열쇠 관리 > 열쇠 파일 동기화 켜기…'에서 켠 뒤 이 버튼을 다시 누르세요.",
        "No listed vault uses key-file sync, so the line has no --key-sync.\n· On a new PC: first bring the vault with 'Bring to this PC…', then press this button again. A vault another PC turned key-file sync on for goes into the line then.\n· For a vault of this PC: turn it on in Goyo Vault under 'Key management > Turn key-file sync on…', then press this button again.",
    ),
    (
        "그중 {}은(는) 서버 쪽 정보(서버 사본이나 서버의 열쇠 파일)만 보고 넣었습니다. 이 PC나 다른 PC에서 직접 열쇠 파일 동기화를 켠 금고가 맞는지 확인하고, 아니면 그 ID를 줄에서 빼세요.",
        "Of these, {} went in only on the server side's word (the server's copy or key file). Check that key-file sync was really turned on for it, on this PC or another; if not, remove its ID from the line.",
    ),
    (
        "열쇠 파일 동기화를 쓰는 금고를 자동으로 넣었습니다: {}. 그 금고를 쓰는 모든 PC의 줄에 같은 금고 ID가 있어야 합니다. 줄을 바꾸면 goyo-sync가 2분 안에 다시 확인합니다(바로 확인하려면 '저장하고 시작'). 열쇠 파일 동기화를 끄고 모든 PC가 받았으면 그 ID를 줄에서 빼세요: 줄에 남은 금고는 이 PC의 동기화 키를 훔친 사람이 업로드를 막을 수 있습니다.",
        "The vaults that use key-file sync were put in automatically: {}. Every PC that uses such a vault needs the same vault ID in its line. Once the line is changed, goyo-sync checks again within two minutes ('Save and start' checks at once). After key-file sync is turned off and every PC took that, remove the ID from the line: whoever steals this PC's sync key can block the uploads of a vault left in it.",
    ),
    (
        "서버의 ~/.ssh/authorized_keys에서 이 PC 전용 키의 줄을 다음 한 줄로 바꾸세요. 공개 키 자리에는 그 키의 .pub 파일 내용을 넣습니다.\n\n{}\n\n이 줄은 이 PC의 전용 키로는 goyo-sync 동기화만 하게 묶습니다(셸·전달 금지). --key-sync=에 적힌 금고만 열쇠 파일을 서버와 주고받을 수 있습니다.\n{}\n\n이 창에서 Ctrl+C를 누르면 창의 글 전체가 복사되니, authorized_keys에는 restrict,command=로 시작하는 그 한 줄만 남기세요.",
        "In ~/.ssh/authorized_keys on the server, replace the line of this PC's dedicated key with the line below. In place of the public key put the content of that key's .pub file.\n\n{}\n\nThis line lets this PC's dedicated key do goyo-sync's sync only (no shell, no forwarding). Only the vaults after --key-sync= can exchange key files with the server.\n{}\n\nCtrl+C in this window copies all of its text, so keep only the one line that starts with restrict,command= in authorized_keys.",
    ),
    (
        "열쇠 변경 자동 적용은 열쇠 파일 동기화를 쓰는 금고에서, 이 PC가 열쇠 파일을 확인한 뒤에만 켤 수 있습니다.",
        "Auto-apply of key changes can be turned on only for a vault that uses key-file sync, after this PC confirmed its key file.",
    ),
    (
        "열쇠 변경 자동 적용이 꺼져 있거나 이 열쇠 파일에는 쓸 수 없어 받지 않았습니다. 처음부터 다시 하세요.",
        "Not taken: auto-apply of key changes is off or does not apply to this key file. Start again.",
    ),
    (
        "열쇠 변경 자동 적용 (이 서버를 믿음)",
        "Auto-apply key changes (trust this server)",
    ),
    (
        "열쇠 변경 자동 적용을 켜면 다른 PC에서 한 열쇠 변경(보안 키 제거, 보안 키 추가, 비밀번호 변경)이 서버로 왔을 때, 어느 키를 잃어버렸는지 고르거나 그 PC의 열쇠 확인 코드를 입력하지 않고 이 PC에 적용합니다. 새 열쇠 파일을 열 때의 보안 키 터치와 비밀번호, 위조를 막는 다른 확인은 그대로입니다.

서버를 장악한 사람이 이 금고의 보안 키 하나와 그 PIN, 그리고 비밀번호까지 함께 갖고 있지 않는 한 안전합니다. 그런 사람이 생기면 그 사람은 이 PC가 자기가 아는 데이터 키로 바꾸게 만들 수 있습니다(그 뒤 저장하는 항목을 읽을 수 있게 됩니다).

이 설정은 이 PC의 이 금고에만 적용되고, 끌 때는 묻지 않습니다. 켤까요?",
        "With auto-apply on, a key change made on another PC (a security key removed, a security key added, a password change) that arrives from the server is applied on this PC without asking which key was lost or for that PC's key check code. The security key touch and the password needed to open the new key file, and the other checks against forgery, stay.

This is safe as long as whoever takes over the server does not also hold one of this vault's security keys with its PIN and your password. If someone ever did, that person could make this PC switch to a data key they know (and read what is saved after that).

This applies to this vault on this PC only, and turning it off asks nothing. Turn it on?",
    ),
    (
        "열쇠 변경 자동 적용을 켰습니다. 서버로 온 열쇠 변경은 [받기…]나 다음 잠금 해제 때 묻지 않고 적용합니다.",
        "Auto-apply of key changes is on. A key change from the server is applied with no question at [Get…] or at the next unlock.",
    ),
    (
        "열쇠 변경 자동 적용을 껐습니다. 서버로 온 열쇠 변경은 다시 잃어버린 키를 고르거나 코드를 입력해야 받습니다.",
        "Auto-apply of key changes is off. A key change from the server again needs the lost keys picked or the code typed.",
    ),
    (
        "열쇠 파일 변경을 적용했습니다: {what}. 열쇠 확인 코드 {code}",
        "Applied the key file change: {what}. Key check code {code}",
    ),
    (
        "보안 키 {list} 제거",
        "security key {list} removed",
    ),
    (
        "이 PC에서 처음 보는 보안 키 {list} 추가",
        "security key {list} new to this PC added",
    ),
    (
        "비밀번호 변경됨",
        "password changed",
    ),
    (
        "열쇠 설정 변경",
        "key settings changed",
    ),
    (
        "다른 PC에서 이 금고의 열쇠를 바꿔 동기화를 멈췄습니다. 새 열쇠 파일은 서버로 옵니다. '열쇠 관리'의 [받기…]로 받거나 다음 잠금 해제 때 받으세요.",
        "Another PC changed this vault's keys, so sync stopped. The new key file comes through the server: take it with [Get…] in 'Key management' or at the next unlock.",
    ),
    (
        "그런 변경을 한 PC가 없다면 서버 사본이 위조되었을 수 있습니다. 그때까지 이 PC의 변경은 이 PC에만 저장됩니다.",
        "If no PC made such a change, the server copy may be forged. Until then, this PC's changes are saved on this PC only.",
    ),
];
