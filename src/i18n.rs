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
        .get_or_init(|| EN.iter().copied().collect())
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
        "'복원할 새 파일'과 같은 이름의 파일이 이미 있습니다. 다른 이름을 지정하세요.",
        "A file with the 'Restore to' name already exists. Choose another name.",
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
        "금고 파일을 찾을 수 없습니다. 경로를 확인하거나 '찾기'로 선택하세요.",
        "Vault file not found. Check the path or choose it with 'Browse'.",
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
        "다른 위치에 있는 금고 열기",
        "Open a vault from another location",
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
        "백업 파일 · '찾기'로 선택",
        "Backup file · choose it with 'Browse'",
    ),
    ("백업에서 복원", "Restore from backup"),
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
    ("복원할 새 파일", "Restore to (new file)"),
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
        "비밀번호 변경 완료. 새 열쇠 파일을 백업하세요. 이전 사본은 자동 폐기되지 않습니다.",
        "Password changed. Back up the new key file; old copies are not revoked.",
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
    ("삭제할 항목을 선택하세요.", "Select an entry to delete."),
    ("새 OTP 6자리 · {tag}", "New OTP code · {tag}"),
    (
        "새 금고 등록을 다시 시작하세요.",
        "Start creating the vault again.",
    ),
    ("새 금고 만들기", "Create a new vault"),
    (
        "새 금고 만들기 · 백업에서 복원",
        "Create a new vault · Restore from backup",
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
        "새 파일 이름을 선택하세요 (기존 파일 덮어쓰기 금지)",
        "Choose a new file name (existing files are never overwritten)",
    ),
    ("새 항목", "New entry"),
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
    ("열림 · {}", "Open · {}"),
    ("열쇠 백업", "Back up key"),
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
        "열쇠 파일은 비밀번호로 암호화되어 있습니다. 금고와 분리 보관하면 보호가 강화됩니다.\r\n분실한 비밀번호·열쇠·OTP를 우회하는 복구 기능은 없습니다.",
        "The key file is encrypted with your password; keeping it apart from the vault adds protection.\r\nThere is no recovery for a lost password, key file or OTP.",
    ),
    (
        "열쇠 파일을 찾을 수 없습니다. USB 등 다른 곳에 두었다면 '찾기'로 선택하세요.",
        "Key file not found. If it is on a USB stick or elsewhere, choose it with 'Browse'.",
    ),
    (
        "열쇠 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.",
        "The key file was changed elsewhere. Lock and open the vault again.",
    ),
    (
        "열쇠 파일이 변경되었습니다. 잠근 뒤 새 비밀번호로 다시 열고 백업하세요.",
        "The key file was changed. Lock, open it again with the new password and back up the key.",
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
        "이 금고는 OTP를 쓰지 않습니다.",
        "This vault does not use an OTP.",
    ),
    (
        "이 열쇠 파일은 OTP를 씁니다. 휴대폰 OTP 앱의 6자리도 입력하세요.",
        "This key file uses an OTP. Also enter the 6-digit code from your phone.",
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
    ("항목 {count}개", "Entries: {count}"),
    ("항목 선택 오류", "Entry selection error"),
    ("항목 수 제한 초과", "Too many entries"),
    ("항목 수정", "Edit entry"),
    ("항목을 삭제했습니다.", "Entry deleted."),
    ("항목을 선택하세요.", "Select an entry."),
    ("항목이 너무 깁니다.", "The entry is too long."),
    ("현재 비밀번호", "Current password"),
    (
        "현재 비밀번호를 확인한 뒤 열쇠 파일을 다시 암호화합니다.",
        "Checks the current password, then re-encrypts the key file.",
    ),
    (
        "현재 비밀번호와 새 OTP 번호를 확인한 뒤 열쇠 파일을 다시 암호화합니다.",
        "Checks the current password and a fresh OTP code, then re-encrypts the key file.",
    ),
    (
        "현재 열쇠 파일만 갱신됩니다. 이전 열쇠와 이전 비밀번호로 이후 금고도 열 수 있습니다. 유출 대응용 키 교체가 아닙니다. 변경 후 새 열쇠 파일을 별도로 백업하세요.",
        "Only the current key file changes. An old key copy with the old password still opens later versions of the vault, so this is no key rotation after a leak. Back up the new key file afterwards.",
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
];
