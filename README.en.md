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
- **Opening a vault takes** the vault file (`.goyo`), a separate key file (`.goyokey`) and your password. You can add a phone OTP if you want (off by default). Only the two files and the password take part in decryption, so **to someone holding both files, the password is the only barrier**. Keep the key file somewhere else.
- **Secrets stay hidden by default:** show for 15 seconds, copy only after you allow it, and the clipboard is wiped 15 seconds after a copy.
- **Auto-lock** of an open vault after 60 seconds idle (2 minutes on the OTP backup screen), after 30 seconds in another app, when you lock the screen, the PC sleeps or Windows shuts down.
- **Screen-capture protection:** the window is excluded from the capture paths Windows supports (ordinary screenshots and screen recordings).
- **A single executable, no installer.** Dark and light themes.

## Requirements

- Windows 11, 64-bit, on a CPU with the RDSEED instruction. Most Intel CPUs from the 5th generation (Broadwell) on and all AMD Ryzen CPUs have it.
- (Only if you turn on the OTP) a TOTP app on your phone: Google Authenticator, or any app that uses the same standard (TOTP, 6 digits, 30 seconds).

## Install

1. Download `GoyoVault-<version>-windows-x64.zip` from [Releases](https://github.com/NA-DEGEN-GIRL/goyo-vault/releases).
2. **Check the download before running it.** The only official source is this repository (`github.com/NA-DEGEN-GIRL/goyo-vault`). In PowerShell run `Get-FileHash .\GoyoVault-<version>-windows-x64.zip` and compare it with the SHA-256 in the release notes. `SHA256SUMS.txt` inside the ZIP only detects corruption: whoever swaps the ZIP can update it too.
3. The ZIP contains a `GoyoVault` folder. Extract it to **a folder only you use that is not synced**, for example `C:\Users\<you>\GoyoVault`. Avoid:
   - the inside of the ZIP or a temporary folder: cleaning it up deletes your vault (the app warns at start-up);
   - `Documents`/`Desktop` backed up by OneDrive, and Dropbox or Google Drive folders: vault and key end up in the same cloud account;
   - a new folder directly under `C:\`, shared folders and USB sticks others use: someone else could replace the program.
4. Run `GoyoVault\goyo-vault.exe`. The program is not code-signed, so Windows SmartScreen may warn you. If the hash matched in step 2, choose **More info → Run anyway**. With Smart App Control enforcing, unsigned programs may be blocked outright.

### Updating

Extract the new ZIP **to the same place, overwriting the old files.** Only the program and documents change; the vault (`.goyo`), key (`.goyokey`) and theme setting in that folder stay. Back up the vault and key first.

Every vault made before 0.5.0 uses an OTP and still opens as before. A vault made **without an OTP** in 0.5.0 or later does not open in 0.4.x or earlier.

> [!NOTE]
> ZIPs before 0.2.0 extracted to a versioned folder such as `GoyoVault-0.1.0`. If you created a vault there, move the vault and key files into the new `GoyoVault` folder, or open them with **Open a vault elsewhere (다른 위치에 있는 금고 열기)**.

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

1. Choose where the **new vault file (새 금고 파일)** and **new key file (새 열쇠 파일)** go. Both default to the program folder, so the key caption warns in red. **Pick another place for the key, such as a USB drive, with Browse (찾기).** In the same folder, anyone who copies the folder only has to guess the password. The app remembers the last vault and key it opened (`goyo-vault.paths`), so a key on a USB drive does not need browsing every time.
2. Enter a **password** twice. It needs at least 12 characters; repeated characters and passwords made only of common words, keyboard walks or number runs (`password1234`, `qwerty123456`, `1q2w3e4r5t6y`) are refused. For seed phrases or private keys use **4–6 unrelated words**. Words from common-password lists such as `dragon` or `sunshine` do not count, so pick uncommon ones. The check only filters the obvious; passing it does not make a password safe. If the key file is stolen, a common password falls to one GPU within a day; four random words are out of reach. Press the eye icon at the right of the field to check what you typed for typos; press it again to hide it.
3. The **phone OTP (휴대폰 OTP)** is optional and off by default. Press **Create vault (금고 만들기)** and you are done.

#### Turning on the OTP

![Create a vault with the OTP on](docs/images/create-otp.png)

With the OTP on, opening the vault also asks for the 6-digit code from your phone's OTP app. That stops someone who saw your password from opening the vault with this app on this PC, but not someone who copied the vault and key files (see [Please read](#please-read)). Losing the phone without an OTP backup locks you out, so turn it on only if that risk is worth it to you. **The choice is made when the vault is created and cannot be changed later.**

1. Press **Use OTP (OTP 사용)** to show the QR. The passwords you typed stay; **Turn off OTP (OTP 끄기)** switches back.
2. In Google Authenticator tap **+ → Scan a QR code** and point it at the QR on screen. Each vault gets its own entry name, such as `Goyo Vault (3FA2-C1D0)`; the same name appears above the OTP field when you open the vault, so with several vaults you can pick the right code. While you are in another app the QR and key are hidden, and **Back (뒤로)** keeps the same QR when you return. If scanning does not work, choose **Enter a setup key** and type the key shown next to the QR (type: **Time based**). The QR and key in the screenshot are fake examples.
3. Enter the **6-digit code** from the app and press **Confirm and create (등록 확인 · 금고 만들기)**.

> [!IMPORTANT]
> - Scan the QR **only with the scanner inside your OTP app.** Pointing an ordinary camera or Google Lens at it, or taking a photo, can leave the secret in your photo library or in the cloud.
> - Losing your phone means you cannot open the vault with this app. After creating it, add the OTP to a spare device with **OTP backup** (step 8 below), or turn on Authenticator's own backup.

### 3. Save an entry

![New entry](docs/images/new-entry.png)

Press **+ New entry (+ 새 항목)**, fill in name, type, secret and note, then press **Encrypt and save (암호화하여 저장)**.

- Type the kind yourself or use the **password · seed phrase · private key · API key** buttons (비밀번호 · 니모닉 · 프라이빗키 · API 키).
- Multi-line keys such as PEM files are kept exactly.
- **Names are always visible in the list,** so never put a secret in the name.
- For safety, the input method editor (IME) is off in the secret and note fields; Korean text has to be pasted there. You can copy a value in another app, but **come back within 30 seconds** to paste it; staying away longer locks the vault and clears unsaved edits.

### 4. View and copy

![Vault](docs/images/vault.png)

Pick an entry in the list to see it on the right.

- **Show for 15 s (15초 보기)** reveals the secret and the note for 15 seconds. Press it again to hide them at once.
- **Copy:** turn on **Allow copy (복사 허용)**, then press **Copy (복사)**. The permission turns itself off after 30 seconds or after one copy.
- A copied value is **wiped from the clipboard after 15 seconds** and is kept out of Win+V clipboard history and cloud clipboard sync.
- Remaining times are shown on screen.

### 5. Lock and open again

![Open vault](docs/images/login.png)

The vault locks itself after 60 seconds without use, after 30 seconds in another app, when you lock the screen or the PC sleeps. **Lock (잠금)** locks it right away.

A quick trip to another app (pasting a copied value, a screenshot tool) does not lock it. The moment you switch, though, **Show for 15 s**, **Allow copy**, any password you made visible and the **OTP backup** QR are hidden. The vault window never appears in screen captures anyway.

Screens before a vault is open (open, new vault, restore) keep what you typed and the OTP setup QR when you switch to another app; only a password you made visible is hidden again. They are still cleared after the idle time (5 minutes for a new vault, 60 seconds otherwise) or when you lock Windows.

To open it again, enter your password. If you moved the vault or key file, pick it with **Browse (찾기)**. For a vault with the OTP on, an OTP field appears to match the chosen key file; enter a **new** code. A code that was already used is refused, so if you just opened the vault, wait for the next code on your phone.

### 6. Back up and restore

Use the buttons at the bottom of the vault screen.

- **Back up vault (금고 백업)** saves the encrypted vault to a new file.
- **Back up key (열쇠 백업)** saves the encrypted key file to a new file. Store it **apart** from the vault backup.
- A failed backup is reported in a dialog box. No dialog means the file was saved.

**Backup rules**
- Keep vault backups and key backups on **at least two different drives**. One USB stick holding both leaves only the password.
- Make a new vault backup after adding or changing entries, especially a new seed phrase.
- Every few months, **actually restore** a backup (it goes to a new file, so the original is safe).
- Do not let this vault be the only copy of a valuable seed phrase; also keep it on paper or metal.

![Restore from backup](docs/images/restore.png)

To restore, press **Restore from backup (백업에서 복원)** on the first-start or open screen. Choose the backup and the key file, enter your password (and the OTP if the vault uses one), and the vault is restored to a new file; the backup itself is not changed. On a new PC the first restore goes to `vault.goyo` by default, and the restored vault is remembered as the last one opened, so the next start offers it directly.

### 7. Change the password

**Change password (비밀번호 변경)** on the vault screen asks for the current password and the new one (and a fresh OTP code if the vault uses one), then re-encrypts the key file. **Back up the key again** afterwards.

### 8. OTP backup (in case you lose your phone)

![OTP backup](docs/images/otp-backup.png)

Only vaults with the OTP on have this. Press **OTP backup (OTP 백업)** at the bottom of the vault screen and enter your current password to see the same QR and setup key as when you created the vault. Add it to a spare phone or another OTP app and it shows the same codes as your phone, so you can still open the vault if the phone is lost. Writing the setup key on paper and keeping it somewhere safe works too.

> [!NOTE]
> Saving the setup key as an entry inside the vault is not a backup: the vault needs the OTP to open, so after losing the phone you could not get that entry out. Move it to another device or to paper **before** the phone is gone.

### 9. Theme

![Light theme](docs/images/light.png)

Choose dark or light in the top-right corner. The choice is stored as just `dark` or `light` in `goyo-vault.theme` next to the executable and has nothing to do with your vault.

## Please read

- **Keep the key file separate. This matters most.** With vault and key in the same folder (the default) or in the same cloud account, whoever takes both only has to keep guessing the password, without any OTP. The app warns about such placements in red.
- **There is no recovery.** Lose the vault file, the key file or the password (or the OTP, if you turned it on) and this app cannot open the vault. There is no way around it. With the OTP on, prepare for a lost phone with **OTP backup**.
- **Do not delete `.goyotmp` files carelessly.** If power fails or a USB stick is pulled during a save, a temporary file such as `vault.goyo.<digits>.goyotmp` may be all that is left. It can be the only copy; rename it back. The app points this out when the main file is missing.
- **The OTP is an extra check inside this app, so it is off by default.** An OTP code changes every 30 seconds and cannot serve as an encryption key, and to check codes the app has to keep the same OTP secret as your phone in the key file. So someone with both files and your password can decrypt the vault without the OTP. What the OTP stops is someone who knows your password opening the vault with this app on this PC. The real extra protection against stolen files is keeping the key file elsewhere.
- **Changing the password does not revoke old key copies.** An old key copy plus the old password still opens later versions of the vault. If you suspect a leak, destroy old copies yourself.
- **Anything you copy can be read by other programs.** Copy only when needed. When you paste into a password or secret field, the app clears the clipboard right away, but it cannot erase what the source app left behind (for example in Win+V history).
- **It cannot protect an infected PC.** A keylogger records the password, and malware running as you can copy the vault and key or replace the program. Malware with administrator rights, kernel attacks and a camera pointed at the screen are also out of reach. Use a hardware wallet for large holdings.

## Security design and limits

<details>
<summary>Details</summary>

**Cryptography**
- **XChaCha20-Poly1305** from RustCrypto: 256-bit key, 192-bit nonce, 128-bit tag. Data and headers are authenticated.
- **Argon2id v1.3** with 256 MiB memory, 3 passes and parallelism 1 derives the key-file encryption key from the password. The key file holds a random data key, plus the OTP secret for vaults with the OTP on.
- Randomness comes from the CPU's **RDSEED** conditioned with SHA-512. Windows CNG, DPAPI, BCrypt random and `getrandom` are not used. The CPU, firmware and any hypervisor are trusted; simple sanity checks do not certify the hardware.
- The file format is documented in [docs/FORMAT.md](docs/FORMAT.md).

**Memory and files**
- On normal exit and on lock, keys, strings, serialization buffers and Argon2 working memory are wiped with `zeroize`. Copies inside Windows input controls, graphics memory, CPU registers, the page file or crash dumps are not guaranteed to be removed.
- No plaintext file is ever written. An encrypted temporary file in the same folder is synced, renamed into place and flushed again under its final name. A file lock prevents two instances from using one vault. The lock goes by path, so two hard links to one vault can still be opened twice; it stops cooperating programs, not malware running as you.
- `goyo-vault.theme` (theme) and `goyo-vault.paths` (last vault and key locations) next to the program hold no secrets. The paths file does reveal where the key is, so do not share that folder.
- Power-loss safety depends on the drive and file system; FAT/exFAT is not guaranteed. `.goyolock` files, encrypted temporary files left after a crash, and metadata such as file names and paths are not hidden.
- Windows device names such as `CON`, `NUL` or `COM1` are refused as file names, because a backup to `NUL` would look successful and keep nothing.

**Screen, input and clipboard**
- Input fields use the Windows password input scope, and the secret and note fields are detached from the IME. Depending on the input method, Korean may not be typeable in other fields either; paste instead. OS text services, third-party keyboards and voice input cannot be fully prevented from learning what you type. If input protection cannot be set up, that field and saving/unlocking are blocked.
- Input fields and the entry list ignore every window message other programs send them, however it is sent, so another program cannot read the text, infer it from character positions or change the list selection. The main window ignores button clicks and commands that other programs send or post, including while a message box or file dialog is open. It also ignores keyboard or mouse input that arrives while the app is not in front, so the mouse wheel does not scroll the list then. A program running as you can still fake input while the app is in front.
- For the same reason, screen readers such as Narrator cannot read the app's input fields or entry list.
- The eye icon in a password field shows the text only when you press it. While shown, copying, reads by other programs, accessibility reads and screen capture stay blocked, and the IME stays off. Locking, the idle timeout, changing screens and switching to another app hide it again. It cannot stop someone looking over your shoulder.
- Values copied by the app are excluded from Win+V history and cloud sync and marked so that clipboard managers honouring the convention do not record them. If another program holds the clipboard, clearing is retried, and closing waits until it succeeds. Windows shutdown and restart also lock and try to clear it; a forced kill cannot guarantee this cleanup. Values that went through the clipboard can leave copies in Windows' own memory.
- Switching apps keeps a just-copied value for the rest of its 15 seconds so you can paste it. Manual lock, screen lock and sleep clear it immediately. Content another app put on the clipboard in the meantime is left alone.
- Capture exclusion only covers capture paths that Windows supports. It cannot stop a camera.
- The enrollment QR is drawn straight to the window by a built-in encoder. No image file is written, no outside service is used, and the intermediate buffers holding the secret are wiped with `zeroize`.

**Process hardening**
- Every DLL the program loads before it starts running is looked up in System32 only; other Windows DLLs are loaded from System32 only, after the defenses are on. Each release is checked by running the program with fake DLLs, and then real copies of System32 DLLs, placed next to it; the check fails if any is loaded from that folder (`scripts/check_dll_planting.py`).
- Right after start the app disables dynamic code, legacy extension points, non-system fonts and remote or low-integrity image loads; from then on it **loads only Microsoft-signed DLLs** and **forbids child processes**. Third-party IMEs and third-party shell extensions in the file dialog therefore do not run inside the app.
- Access to the process and all its threads is narrowed so other programs running as you cannot read or write the app's memory or start threads in it to inject code. Threads Windows starts later (for example for a file dialog) get the same restriction within 0.5 seconds. Programs with administrator (debug) rights are not stopped.
- An attached user-mode debugger or a Remote Desktop (RDP) session locks the vault or blocks actions. These are best-effort checks that can be bypassed; they do not detect remote-control tools such as TeamViewer, memory reading or keyloggers, and the app never claims that the PC is "safe".
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

- `python scripts/package_release.py` builds the release ZIP. It refuses to run with uncommitted sources or `RUSTFLAGS` set, strips the build machine's paths from the executable (and stops if any remain), and only packages a binary that passes the PE flag and DLL list check (`scripts/inspect_pe.py`) and the DLL planting check (`scripts/check_dll_planting.py`).
- Releases are built with rustc 1.98.1. The `/Brepro` linker option makes builds comparable: the same toolchain and commit should give the same executable.
- `scripts/make_icon.ps1` regenerates the icon; `build.rs` embeds `assets/goyo.ico` into the executable.
- `cargo test ui_preview -- --ignored` renders every screen to `test-output/ui-preview/`. It briefly shows a preview window.

There is no network code, telemetry, auto-update or code that starts other programs. The C runtime is linked statically.

## License

[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. Licenses of the libraries used are in [docs/THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md).
