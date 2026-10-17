<p align="center"><img src="docs/images/icon.png" width="96" alt=""></p>
<h1 align="center">Goyo Vault · 고요 금고</h1>
<p align="center">An offline vault for passwords, seed phrases and private keys that stays on your PC (Windows 11)</p>
<p align="center"><a href="README.md">한국어</a> · <b>English</b></p>

![Goyo Vault](docs/images/vault.png)

> [!WARNING]
> This is a development release. It has automated tests and AI-assisted code reviews, but **it has not had a professional security audit.** Try creating, backing up and restoring a vault with fake values before you trust it with real secrets.

> [!NOTE]
> The interface is in Korean only for now. This guide gives the Korean label of every button next to its English meaning, e.g. **New vault (새 금고 만들기)**.

## What it does

- **Fully offline:** no network code, no server, account, sync or auto-update.
- **Four things open a vault:** the vault file (`.goyo`), a separate key file (`.goyokey`), your password and a phone OTP.
- **Secrets stay hidden by default:** show for 15 seconds, copy only after you allow it, and the clipboard is wiped 15 seconds after a copy.
- **Auto-lock** after 60 seconds idle, when you switch to another app, lock the screen or the PC sleeps.
- **Screen-capture protection:** the window is excluded from ordinary screenshots and screen recordings.
- **A single executable, no installer.** Dark and light themes.

## Requirements

- Windows 11, 64-bit, on a CPU with the RDSEED instruction. Most Intel CPUs from the 5th generation (Broadwell) on and all AMD Ryzen CPUs have it.
- A TOTP app on your phone: Google Authenticator, or any app that uses the same standard (TOTP, 6 digits, 30 seconds).

## Install

1. Download `GoyoVault-<version>-windows-x64.zip` from [Releases](https://github.com/NA-DEGEN-GIRL/goyo-vault/releases).
2. Extract it to **a folder you will keep**, for example `Documents\GoyoVault`. Do not run it from inside the ZIP. The vault is saved next to the executable by default, so a temporary folder that gets cleaned up would take your vault with it.
3. Run `goyo-vault.exe`. The program is not code-signed, so Windows SmartScreen may warn you. Choose **More info → Run anyway**. You can check the download against `SHA256SUMS.txt` inside the ZIP.

## How to use it

### 1. First start

![First start](docs/images/welcome.png)

With no vault saved yet, you see this screen ("No vault saved yet").

- **New vault (새 금고 만들기)** if this is your first time.
- **Restore from backup (백업에서 복원)** to bring over a vault from another PC.
- **Open a vault elsewhere (다른 위치에 있는 금고 열기)** for a vault on a USB drive or in another folder.

Switch between **Dark (다크)** and **Light (라이트)** in the top-right corner.

### 2. Create a vault

![Create a vault](docs/images/create.png)

1. Check where the **new vault file (새 금고 파일)** and **new key file (새 열쇠 파일)** go. Both default to the program folder. Keeping the key file somewhere else, such as a USB drive, is safer.
2. Enter a **password** twice. It needs at least 16 characters, and passwords that just repeat a few characters are refused. A long sentence you can remember is better than a short complex one.
3. In Google Authenticator tap **+ → Scan a QR code** and point it at the QR on screen. If scanning does not work, choose **Enter a setup key** and type the key shown next to the QR (type: **Time based**). The QR and key in the screenshot are fake examples.
4. Enter the **6-digit code** from the app and press **Confirm and create (등록 확인 · 금고 만들기)**.

> [!IMPORTANT]
> - Scan the QR **only with the scanner inside your OTP app.** Pointing an ordinary camera or Google Lens at it, or taking a photo, can leave the secret in your photo library or in the cloud.
> - The QR and setup key are shown only on this screen. In case you lose your phone, turn on Authenticator's own backup or write the setup key on paper and keep it somewhere safe.

### 3. Save an entry

![New entry](docs/images/new-entry.png)

Press **+ New entry (+ 새 항목)**, fill in name, type, secret and note, then press **Encrypt and save (암호화하여 저장)**.

- Type the kind yourself or use the **password · seed phrase · private key · API key** buttons (비밀번호 · 니모닉 · 프라이빗키 · API 키).
- Multi-line keys such as PEM files are kept exactly.
- **Names are always visible in the list,** so never put a secret in the name.
- For safety, the input method editor (IME) is off in the secret and note fields; Korean text has to be pasted there. Switching to another app clears unsaved edits, so **copy what you want to paste before you open the editor.**

### 4. View and copy

![Vault](docs/images/vault.png)

Pick an entry in the list to see it on the right.

- **Show for 15 s (15초 보기)** reveals the secret and the note for 15 seconds. Press it again to hide them at once.
- **Copy:** turn on **Allow copy (복사 허용)**, then press **Copy (복사)**. The permission turns itself off after 30 seconds or after one copy.
- A copied value is **wiped from the clipboard after 15 seconds** and is kept out of Win+V clipboard history and cloud clipboard sync.
- Remaining times are shown on screen.

### 5. Lock and open again

![Open vault](docs/images/login.png)

The vault locks itself after 60 seconds without use, when you switch to another app, lock the screen or the PC sleeps. **Lock (잠금)** locks it right away.

To open it again, enter your password and a **new** OTP code. A code that was already used is refused, so if you just opened the vault, wait for the next code on your phone. If you moved the vault or key file, pick it with **Browse (찾기)**.

### 6. Back up and restore

Use the buttons at the bottom of the vault screen.

- **Back up vault (금고 백업)** saves the encrypted vault to a new file.
- **Back up key (열쇠 백업)** saves the encrypted key file to a new file. Store it **apart** from the vault backup.

![Restore from backup](docs/images/restore.png)

To restore, press **Restore from backup (백업에서 복원)** on the first-start or open screen. Choose the backup and the key file, enter your password and OTP, and the vault is restored to a new file; the backup itself is not changed. On a new PC the first restore goes to `vault.goyo` by default, so the next start opens it directly.

### 7. Change the password

**Change password (비밀번호 변경)** on the vault screen asks for the current password, the new one and a fresh OTP, then re-encrypts the key file. **Back up the key again** afterwards.

### 8. Theme

![Light theme](docs/images/light.png)

Choose dark or light in the top-right corner. The choice is stored as just `dark` or `light` in `goyo-vault.theme` next to the executable and has nothing to do with your vault.

## Please read

- **There is no recovery.** Lose the vault file, the key file, the password or the OTP and the vault cannot be opened. There is no way around it.
- **Keep the key file separate.** With vault and key in the same folder, both can be lost or stolen together.
- **The OTP is an extra check inside this app.** Someone with both files and your password can decrypt the vault without it. The real extra protection against stolen files is keeping the key file elsewhere.
- **Changing the password does not revoke old key copies.** An old key copy plus the old password still opens later versions of the vault. If you suspect a leak, destroy old copies yourself.
- **Anything you copy can be read by other programs.** Copy only when needed. When you paste into a password or secret field, the app clears the clipboard right away, but it cannot erase what the source app left behind (for example in Win+V history).
- **It cannot protect an infected PC.** Keyloggers, malware with administrator rights, kernel attacks or a camera pointed at the screen are out of reach.

## Security design and limits

<details>
<summary>Details</summary>

**Cryptography**
- **XChaCha20-Poly1305** from RustCrypto: 256-bit key, 192-bit nonce, 128-bit tag. Data and headers are authenticated.
- **Argon2id v1.3** with 256 MiB memory, 3 passes and parallelism 1 derives the key-file encryption key from the password. The key file holds a random data key and the OTP secret.
- Randomness comes from the CPU's **RDSEED** conditioned with SHA-512. Windows CNG, DPAPI, BCrypt random and `getrandom` are not used. The CPU, firmware and any hypervisor are trusted; simple sanity checks do not certify the hardware.
- The file format is documented in [docs/FORMAT.md](docs/FORMAT.md).

**Memory and files**
- On normal exit and on lock, keys, strings, serialization buffers and Argon2 working memory are wiped with `zeroize`. Copies inside Windows input controls, graphics memory, CPU registers, the page file or crash dumps are not guaranteed to be removed.
- No plaintext file is ever written. An encrypted temporary file in the same folder is synced and then renamed into place. A file lock prevents two instances from using one vault; it stops cooperating programs, not malware running as you.
- Power-loss safety depends on the drive and file system; FAT/exFAT is not guaranteed. `.goyolock` files, encrypted temporary files left after a crash, and metadata such as file names and paths are not hidden.
- Windows device names such as `CON`, `NUL` or `COM1` are refused as file names, because a backup to `NUL` would look successful and keep nothing.

**Screen, input and clipboard**
- Input fields use the Windows password input scope, and the secret and note fields are detached from the IME. Depending on the input method, Korean may not be typeable in other fields either; paste instead. OS text services, third-party keyboards and voice input cannot be fully prevented from learning what you type. If input protection cannot be set up, that field and saving/unlocking are blocked.
- Values copied by the app are excluded from Win+V history and cloud sync and marked so that clipboard managers honouring the convention do not record them. If another program holds the clipboard, clearing is retried, and closing waits until it succeeds. A forced kill or a system shutdown cannot guarantee this cleanup.
- Switching apps locks the vault but keeps a just-copied value for the rest of its 15 seconds so you can paste it. Manual lock, screen lock and sleep clear it immediately. Content another app put on the clipboard in the meantime is left alone.
- Capture exclusion only covers capture paths that Windows supports.
- The enrollment QR is drawn straight to the window by a built-in encoder. No image file is written, no outside service is used, and the intermediate buffers holding the secret are wiped with `zeroize`.

**Process hardening**
- At start-up the app disables dynamic code, legacy extension points, non-system fonts and remote or low-integrity image loads, **loads only Microsoft-signed DLLs** and **forbids child processes**. Third-party IMEs, third-party shell extensions in the file dialog and DLLs injected at run time therefore do not run inside the app.
- Debuggers, remote sessions and broken capture protection lock the vault or block actions. This is not a full malware or keylogger detector, and the app never claims that the PC is "safe".
- Rolling a vault back to an old backup, resetting the retry delay by restarting the app, and malicious apps bypassing the checks cannot be fully prevented without a server or separate trusted hardware.
- 256-bit symmetric keys are used, but no post-quantum certification or guarantee is claimed.

Review notes (in Korean): [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).

</details>

## Building from source

You need the stable Rust MSVC x64 toolchain and its linker. No GUI or crypto SDK is used. The only direct dependencies are Rust crates for cryptography and secret handling, pinned in `Cargo.toml` and `Cargo.lock`.

```powershell
cargo test --locked -- --test-threads=1
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
python scripts/check_dependencies.py
target/release/goyo-vault.exe --self-check
```

- `python scripts/package_release.py` builds the release ZIP. It strips the build machine's paths from the executable and refuses to package if a user name or local path is still inside.
- `scripts/make_icon.ps1` regenerates the icon; `build.rs` embeds `assets/goyo.ico` into the executable.
- `cargo test ui_preview -- --ignored` renders every screen to `test-output/ui-preview/`. It briefly shows a preview window.

There is no network code, telemetry, auto-update or code that starts other programs. The C runtime is linked statically.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Licenses of the libraries used are in [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md).
