# Android 앱 (1단계)

`android/` 폴더는 고요 금고의 Android 앱입니다. 1단계는 **PC에서 만든 금고를 휴대폰에서 여는 것**까지입니다: 금고 파일과 열쇠 파일을 앱으로 가져오고, 비밀번호와 YubiKey(NFC 또는 USB-C)로 열고, 항목을 보고 복사하고 고칩니다. 동기화(Tailscale)는 다음 단계입니다. 화면은 한국어만 있습니다(영어는 나중에).

암호와 파일 형식은 PC와 **같은 Rust 코드**(`goyo_vault` 라이브러리)가 처리합니다. Kotlin 쪽은 화면, 파일 가져오기, YubiKey와의 통신만 합니다. 키, 파생 키, 금고의 평문은 Rust 밖으로 나가지 않고, 화면에 보이는 항목의 글자만 나갑니다.

## 구성

| 위치 | 내용 |
| --- | --- |
| `src/posix.rs`, `src/crypto.rs` 등 | 라이브러리의 Linux/Android 구현: 커널 난수(getrandom), rename(2)+fsync 저장, O_NOFOLLOW 읽기, (st_dev, st_ino) 파일 식별, flock 잠금, `vault::set_anchor_root` |
| `android/rust` | JNI 다리(`libgoyo_android.so`, `app.goyovault.Native`). `jni` 크레이트는 여기에만 씁니다 |
| `android/app` | 앱(Kotlin, Jetpack Compose, minSdk 28, compile/target 36, `app.goyovault`). YubiKey는 Yubico의 yubikit-android 3.1.0 |
| `android/rust/examples/make_test_vault.rs` | 기기 시험용 **시험 금고**(비밀번호만, 가짜 항목)를 PC에서 만드는 프로그램 |

yubikit-android는 3.1.0을 씁니다. 3.2.0부터는 compileSdk 37이 필요해서 compile 36에 맞췄습니다.

## 빌드

준비물(이 PC에 이미 있음):

- JDK 21 (`JAVA_HOME`), Android SDK (platform 36, build-tools, platform-tools)
- NDK `30.0.16248370` (`ANDROID_NDK_HOME`, 없으면 SDK의 `ndk/30.0.16248370`)
- `rustup target add aarch64-linux-android`, `cargo install cargo-ndk`
- `android/local.properties`에 `sdk.dir=...` (git에 올리지 않습니다)

```powershell
$env:JAVA_HOME = "$env:LOCALAPPDATA\Programs\jdk-21"
cd android
.\gradlew.bat assembleDebug
adb install -r app\build\outputs\apk\debug\app-debug.apk
```

`assembleDebug`가 먼저 `cargo ndk -t arm64-v8a --platform 28 build --release`로 `android/rust`(와 그 안의 금고 라이브러리)를 빌드해 `app/build/rustJniLibs`에 넣습니다. Argon2id(256 MiB)는 최적화 없이는 너무 느려서 디버그 APK도 Rust는 release로 빌드합니다. arm64-v8a(64비트 ARM) 휴대폰만 지원합니다.

PC 쪽 점검 `python -X utf8 scripts/run_checks.py`는 NDK, cargo-ndk, aarch64 타깃이 있으면 라이브러리를 Android용으로도 검사합니다(clippy, 두 판). 없으면 "NOTE: Android lib check skipped: ..."를 찍고 넘어갑니다.

### 기기에서 자동 시험

1. 라이브러리 시험 전체를 휴대폰에서 돌리기(선택):

   ```powershell
   cargo ndk -t arm64-v8a --platform 28 test --lib --no-run
   adb push target\aarch64-linux-android\debug\deps\goyo_vault-<해시> /data/local/tmp/goyo-lib-tests
   adb shell "mkdir -p /data/local/tmp/goyo-tests && cd /data/local/tmp/goyo-tests && TMPDIR=/data/local/tmp/goyo-tests /data/local/tmp/goyo-lib-tests"
   ```

   Windows에서만 생기는 상황을 흉내 내는 13개 시험(열린 핸들이 교체를 막음, 읽기 전용 속성, Windows 경로, Android가 막는 하드 링크)은 Unix에서 `ignored`로 나옵니다. 나머지는 모두 통과해야 합니다(1단계 마지막 실행: 261 통과, 13 ignored).

2. 앱 안(앱의 샌드박스와 SELinux 영역)에서 JNI와 라이브러리 시험:

   ```powershell
   cd android\rust
   cargo run --release --example make_test_vault   # app\build\testVault 에 시험 금고
   cd ..
   .\gradlew.bat connectedDebugAndroidTest
   ```

   시험 금고를 열고, 틀린 비밀번호를 거부하고, 항목을 읽고, 추가·삭제·저장한 뒤 다시 엽니다. 시험 금고의 비밀번호는 코드에 적힌 가짜 값이고, 만드는 프로그램은 PC의 열쇠 기록(`%LOCALAPPDATA%\GoyoVault`)을 건드리지 않습니다. `connectedDebugAndroidTest`는 끝나면 앱을 지우므로, 다시 `adb install -r`로 설치하세요(가져온 금고도 지워집니다).

## 직접 해 볼 것 (실제 YubiKey)

YubiKey가 필요한 부분은 자동 시험으로 확인하지 못했습니다. 아래 순서로 확인해 주세요. **진짜 금고 말고 시험 금고로** 하세요.

1. **PC에서 시험 금고 만들기.** `goyo-vault.exe`의 '만들기'에서 새 파일 이름(예: `android-test.goyo`, `android-test.goyokey`)과 가짜 비밀번호를 정하고 **보안 키로도 잠그기**를 켜서 YubiKey를 등록합니다(PIN 포함, 가능하면 2개). 가짜 항목을 두어 개 넣습니다.
2. **PC에서 열쇠 확인 코드 적어 두기.** '열쇠 관리'에 보이는 `E… · XXXX-XXXX-XXXX-XXXX`입니다. 휴대폰에서 처음 열면 이 코드를 물을 수 있습니다(아래 6).
3. **휴대폰으로 복사.** USB 케이블(파일 전송)로 두 파일을 휴대폰의 `Download` 등에 복사합니다. 클라우드 드라이브나 메신저는 쓰지 마세요.
4. **가져오기.** 앱의 **금고 가져오기** → 금고 파일(.goyo) → 열쇠 파일(.goyokey) 순서로 고릅니다. 두 파일은 앱만 읽을 수 있는 곳에 **복사**됩니다. 가져온 뒤 `Download`의 사본은 지우세요.
5. **NFC로 열기.** 비밀번호와 YubiKey PIN을 입력하고 **열기** → "YubiKey를 대거나 꽂으세요"가 나오면 키를 휴대폰 뒷면(NFC 위치)에 대고 끝날 때까지 떼지 마세요. 몇 초 뒤(Argon2) 목록이 나오면 성공입니다.
   **USB-C로 열기.** 같은 순서로 하되 키를 꽂습니다. Android가 USB 접근을 물으면 허용하고, 키가 깜박이면 금속 부분을 만집니다.
6. **처음 연 금고는 읽기 전용.** 보안 키가 있는 금고를 이 휴대폰에서 처음 열면, PC처럼 "이 기기에서 처음 연 금고라 지금은 읽기만 됩니다"가 나옵니다(TOFU). 2에서 적은 코드를 입력하면 고칠 수 있게 됩니다. 확인할 PC가 없을 때만 **코드 없이 이 열쇠 파일 믿기…**를 쓰세요.
7. **확인할 것:** 틀린 PIN(남은 횟수 주의, 한두 번만), 등록하지 않은 다른 YubiKey, 틀린 비밀번호가 각각 알맞은 메시지로 거부되는지. 항목 **복사** 뒤 30초가 지나면 클립보드가 비는지. 홈 버튼을 누르거나 화면을 끄면 바로 잠기는지, 3분 동안 손대지 않으면 잠기는지. 최근 앱 화면과 스크린샷에 내용이 나오지 않는지.

**주의: 1단계에는 동기화가 없습니다.** 휴대폰에서 고친 항목은 휴대폰에만 있고 PC로 가지 않습니다. PC에서 다시 가져오면 휴대폰의 변경은 사라집니다. PC에서 열쇠를 바꾸면(키 추가·제거, 비밀번호 변경) 두 파일을 다시 가져오세요. 1단계는 "읽기 위주"로 쓰세요.

1단계 앱이 아직 하지 않는 것: 열쇠 변경(키 추가·제거, 비밀번호 변경), 키 등록, 예전 금고 파일 확인(S-OLDER), 관문 코드(다른 기기에서 바뀐 열쇠 파일), 백업, 여러 금고. 이런 상태의 파일은 "PC의 고요 금고에서 먼저 연 뒤 다시 가져오세요"로 거부합니다.

## Windows와 보안이 다른 점

같은 파일 형식, 같은 암호(Argon2id 256 MiB, XChaCha20-Poly1305, YubiKey hmac-secret)이고, YubiKey 요청도 PC와 같습니다(RP ID `goyo-vault.invalid`, 소금을 해시 없이 그대로, PIN(UV) 필수). 키의 응답은 PC와 같은 코어 검사(`fido::check_assertion`: 요청한 자격 증명인지, rpIdHash, UP, UV, BE/BS 거부, USB/NFC 전송)를 거친 뒤에야 열쇠 파일을 엽니다. 다른 점은 다음과 같습니다.

- **PIN을 앱이 받습니다.** PC에서는 Windows의 보안 창이 PIN을 받지만, Android에는 그런 시스템 창이 없어 앱의 입력 칸에 넣고 yubikit이 키에 보냅니다. 앱은 PIN을 저장하지 않고 쓰고 나면 지웁니다. 그래도 키보드 앱(IME)은 입력을 봅니다.
- **키보드(IME).** 비밀번호·PIN·비밀정보 칸은 비밀번호 입력 칸(자동 수정·학습 끔)이지만, 무엇을 하는지는 키보드 앱에 달렸습니다. 클라우드 동기화나 '입력 학습'을 하는 서드파티 키보드는 쓰지 마세요.
- **자동 완성(비밀번호 관리자).** 앱 창 전체를 자동 완성에서 뺐습니다(`IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS`). 개발 중 이것이 없을 때는 Google 자동 완성이 비밀정보 칸에 "비밀번호 잠금 해제" 제안을 띄웠고, 그 사이 입력이 깨졌습니다(공백이 든 비밀번호가 틀림). 다른 자동 완성 앱을 쓴다면 이 앱에서 아무것도 제안·저장하지 않는지 확인하세요.
- **접근성 서비스.** 화면 읽기나 자동화 앱처럼 접근성 권한을 받은 앱은 화면 글자와 입력 칸을 읽을 수 있고, `FLAG_SECURE`로도 막지 못합니다. Compose의 비밀번호 칸은 접근성 트리에 **실제 글자**를 내놓습니다(개발 중 `uiautomator dump`로 확인). 믿지 않는 접근성 서비스는 꺼 두세요.
- **화면.** 모든 창(대화상자 포함)에 `FLAG_SECURE`를 켜서 스크린샷, 화면 녹화, 최근 앱 미리보기를 막습니다. 앱이 뒤로 가거나 화면이 꺼지면 바로, 3분 동안 손대지 않으면 잠급니다.
- **같은 곳에 있는 두 파일.** PC에서는 열쇠 파일을 USB에 따로 둘 수 있지만, 휴대폰에서는 금고 파일과 열쇠 파일이 같은 앱 저장소에 있습니다. 휴대폰을 통째로 가진 사람에게 남는 장벽은 비밀번호와 YubiKey(와 PIN)입니다. 보안 키 없는 금고(비밀번호만)는 휴대폰에서 PC보다 약하니, 휴대폰에는 **보안 키를 켠 금고만** 가져오기를 권합니다.
- **샌드박스.** 가져온 파일과 이 기기의 열쇠 기록(`GoyoVault/goyo-vault.keys`, PC의 `%LOCALAPPDATA%\GoyoVault`에 해당)은 앱 전용 저장소에 있어 다른 앱이 읽지 못합니다. 앱을 지우거나 '데이터 삭제'를 하면 열쇠 기록도 사라지고, 다시 가져오면 처음 연 금고(TOFU)가 됩니다.
- **루팅·부트로더 해제.** 루팅한 휴대폰이나 악성 루트 앱은 앱 저장소와 열려 있는 금고의 메모리를 읽을 수 있습니다. 잠긴 상태의 파일은 여전히 비밀번호와 YubiKey가 지키지만, 연 동안의 내용은 지키지 못합니다. 루팅한 휴대폰에서는 쓰지 마세요.
- **백업 꺼짐.** `allowBackup=false`이고 클라우드 백업과 기기 간 이전 규칙도 모두 제외합니다. 새 휴대폰으로는 옮겨지지 않으니 PC에서 다시 가져오세요.
- **네트워크 없음.** 1단계 앱에는 인터넷 권한이 없습니다(합쳐진 매니페스트에서도 지움).
- **난수.** PC는 CPU의 RDSEED만 씁니다. ARM에는 앱이 쓸 RDSEED가 없어서, Android에서는 커널 난수(getrandom(2), 풀이 처음 채워질 때까지 기다림)를 같은 SHA-512 조건화를 거쳐 씁니다. 실패하면 더 약한 난수로 대체하지 않고 멈춥니다.
- **클립보드.** 복사한 비밀정보는 '민감' 표시(Android 13 이상에서 미리보기·키보드 제안에서 숨김)를 하고 30초 뒤 지웁니다. Android 10~12(예: LG G7)는 이 표시를 모르므로, 키보드의 클립보드 기록 기능이 사본을 남길 수 있습니다. 앱이 뒤에 있을 때는 클립보드를 읽을 수 없어, 그 30초 안에 다른 앱에서 복사한 것도 함께 지울 수 있습니다.
- **메모리.** Rust 쪽 비밀(비밀번호 사본, 키, hmac-secret 출력)은 다 쓰면 0으로 지웁니다. Kotlin 쪽은 바이트 배열을 지우지만, 입력 칸과 화면에 보인 글자(Java 문자열)는 지울 수 없고 가비지 컬렉터가 치울 때까지 메모리에 남을 수 있습니다.
- **파일 저장.** 임시 파일에 쓰고 fsync한 뒤 rename(2)으로 바꾸고 폴더도 fsync합니다. 링크를 따라가지 않고(O_NOFOLLOW) 읽고, 파일 잠금은 flock입니다. Android는 앱이 하드 링크를 만드는 것을 막아서, "새 파일만 만들기" 저장은 고요 금고의 파일 잠금 안에서 확인 후 rename하는 두 단계로 합니다(1단계 앱은 이 저장을 쓰지 않습니다).

## 알려진 위험과 남은 일

- 실제 YubiKey(NFC, USB-C)로 여는 것은 아직 사람이 확인해야 합니다(위 '직접 해 볼 것'). 파일 가져오기(SAF 파일 선택 창)도 사람이 확인해야 합니다. 개발 중에는 비밀번호만 쓰는 시험 금고를 `run-as`로 앱 저장소에 넣고 화면을 adb로 눌러, 열기(공백 든 비밀번호 포함)·항목 보기·복사·추가·잠그기·뒤로 가면 잠김을 확인했고, 화면 캡처는 `FLAG_SECURE` 때문에 빈 파일이 되었습니다.
- 여러 자격 증명이 든 YubiKey에서 어느 것이 이 금고 것인지는 PIN 토큰으로 조용히 미리 묻고(up=false) 고릅니다. yubikit 자체 클라이언트와 같은 방식입니다.
- 동기화 단계에서 손볼 것: Unix에는 파일 생성 시각이 없고 수정 시각이 거칠어서, 동기화 폴더의 변경 감지(`syncfile::Stamp`)를 Android에 맞게 바꿔야 합니다.
