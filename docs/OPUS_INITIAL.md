**Result:** No concrete defect found in the cryptographic core: AEAD use, AAD binding, nonce and salt generation, key and data parsing, and length bounds all look correct. The actionable issues are in the Win32 layer: DLL loading, clipboard clearing, reentrant message handling, dialog flags, edit-control styles and memory hygiene.

This is an independent read-only review by claude-opus-5-5. It is not a formal audit and makes no claim of malware resistance. No files were modified and no tools were run.

**Missing context**
- Redaction artifacts (`[SECRET]]`, `[PHONE]`) corrupt several lines:
  - `const SECRET`
  - `let mut secret = [SECRET] in `SAVE`
  - `Screen::Password =[SECRET]]] {`
  - the `password:[SECRET] and `secret:[SECRET] parameter types and `Entry.secret`
  - the RFC 6238 vectors

  I assumed these are `&str` / `Zeroizing<String>`.
- Not provided: `scripts/check_dependencies.py`, `docs/dependency-audit.json`, the linked import table, and any app manifest.
- The attachments have no line numbers, so locations are given as file + function.

## Findings

### 1. Medium – DLL planting through static imports, before any mitigation runs
- **Where:** `win.rs`, `#[link(name = "dwmapi")]` and `#[link(name = "wtsapi32")]`; `initialize_defenses`.
- **Scenario:**
  - Neither DLL is a KnownDLL, so the loader resolves them at process start with the application directory searched first.
  - Running the exe from a USB stick or Downloads folder that contains a planted `dwmapi.dll` or `wtsapi32.dll` executes attacker code before `main`.
  - `SetDefaultDllDirectories(0x800)` and the mitigation policies only apply afterwards, so they never take effect.
- **Fix:**
  - Add `"-C", "link-arg=/DEPENDENTLOADFLAG:0x800"` to rustflags, or resolve these APIs through `LoadLibraryExW(…, LOAD_LIBRARY_SEARCH_SYSTEM32)`.
  - Run `dumpbin /imports` and check every non-KnownDLL import, including std's `bcryptprimitives`.
  - Test with Process Monitor from a writable folder.

### 2. Medium – Clipboard auto-clear can silently never fire
- **Where:** `win.rs` `copy_secret` and `clear_clip`.
- **Scenario:**
  - `copy_secret` samples the sequence number before `_close` drops, i.e. before `CloseClipboard`.
  - `clear_clip` treats any sequence change as "another app replaced it" and returns `true` without clearing.
  - The number can advance without the content being replaced: at close, or when a pasting app or clipboard monitor triggers delayed rendering of synthesized `CF_TEXT`/`CF_OEMTEXT`.
  - In that case the secret stays on the clipboard indefinitely while the UI says 15 s. No test covers this path.
- **Fix:**
  - Make `GetClipboardOwner() == h` the primary test. Any replacement must call `EmptyClipboard`, which changes the owner.
  - Sample the sequence after `CloseClipboard`, if you keep it at all.
  - Add a manual test: copy, paste into Notepad and into an ANSI app, then confirm the clipboard is cleared at 15 s.

### 3. Low–Medium (rare trigger, severe outcome) – Deferred security events leave a hidden, unlocked window
- **Where:** `main.rs` `window_proc`, the `try_borrow_mut` failure branch. `PENDING_LOCK` is consumed only in the `0x111` arm.
- **Scenario:**
  - A reentrant `WM_ACTIVATEAPP`, WTS session change or suspend can arrive while `APP` is borrowed by `timer`, `paint` or either `modal_command` scope.
  - The handler sets the flag and hides the window, but nothing else ever reads the flag.
  - The session stays decrypted until the idle lock (60 s, or 300 s with a provision).
  - The window stays hidden forever: only the `0x111` arm re-shows it, and a hidden window cannot receive the clicks that produce `WM_COMMAND`.
  - Even in the `0x111` arm, `lock(…, false)` skips clipboard clearing for session lock and suspend, contrary to the README.
  - Reentrant `WM_CLOSE` and `WM_PAINT` fall through to `DefWindowProc`. A destroyed owner window makes `clear_clip` give up (owner ≠ h), so the copied secret stays on the clipboard.
- **Fix:**
  - After every `APP.with` scope, including in `timer()` and `modal_command`, drain a pending-event value.
  - Record which event occurred, lock with clipboard clearing for WTS and suspend events, then `ShowWindow(h, SW_SHOW)`.
  - While borrowed, return 0 for `WM_CLOSE` and re-post it instead of passing it to `DefWindowProc`.

### 4. Low–Medium – File dialogs record vault and key locations in MRU lists
- **Where:** `win.rs` `dialog`, flag `0x10000000`.
- **Scenario:**
  - `0x10000000` is `OFN_FORCESHOWHIDDEN`. `OFN_DONTADDTORECENT` is `0x02000000`.
  - Every browsed or backup path, including a key file on a separate USB drive, goes into `ComDlg32\OpenSavePidlMRU`, `LastVisitedPidlMRU` and Recent Items.
  - This undermines the vault/key separation control.
- **Fix:** Use `0x02000000`. Drop `0x10000000` unless showing hidden files was intended.

### 5. Medium (correctness) – Notes field accepts only typed digits, and Enter cannot add lines
- **Where:** `main.rs` `App::input`, multiline style `0x2044`.
- **Scenario:**
  - `0x2000` is `ES_NUMBER`. `ES_WANTRETURN` is `0x1000`.
  - Typed letters and Hangul are rejected in 메모, although paste bypasses the filter.
  - Enter goes to `IsDialogMessageW` and becomes an ignored IDOK.
- **Fix:** Use `0x1044`, plus `WS_VSCROLL`.

### 6. Low–Medium (silent data loss) – Multi-line secrets are truncated on paste
- **Where:** `build_edit`, the single-line `ES_PASSWORD` SECRET field.
- **Scenario:**
  - Pasting a PEM private key or a line-separated mnemonic keeps only the first line.
  - The field is masked, so the user may save only `-----BEGIN PRIVATE KEY-----`.
  - `ES_PASSWORD` also disables the IME, so Hangul secrets cannot be typed.
- **Fix:**
  - Intercept `WM_PASTE` in `edit_proc` and read `CF_UNICODETEXT`.
  - Refuse text containing CR/LF with a message, or normalise newlines to spaces explicitly.
  - Alternatively, show the length or first and last characters before saving.

### 7. Low – Error messages reveal whether the password or the OTP was wrong
- **Where:** `Session::load` returns `AUTH_ERROR` for key failures but specific `otp::verify` messages; `submit` shows `e` directly.
- **Scenario:**
  - Someone at the login screen without the phone learns when the password and key are correct.
  - "이미 사용되었습니다" also confirms that a code was valid.
  - Backoff resets on restart. Timing is dominated by Argon2, so the messages are the leak.
- **Fix:**
  - Check the 6-digit format before Argon2.
  - After that, map every unlock or restore failure to `AUTH_ERROR`.

### 8. Low – Password change requires no re-authentication
- **Where:** `submit` Password branch; `Session::change_password`.
- **Scenario:** Anyone at an unlocked session (up to 60 s) can rewrap the live key file under their own password, locking the owner out of it. They could already read the secrets, so the main impact is lockout.
- **Fix:** Require the current password (decrypt `key_bytes`) and a fresh OTP that advances the watermark.

### 9. Low – Zeroization gaps from reallocation
- **Where:**
  - `App::read` uses `String::from_utf16_lossy`.
  - `secret_wide` uses `encode_utf16().chain().collect()`.
  - `clear_controls` overwrites edits with `" ".repeat(8192)`.
- **Scenario:**
  - Both collects grow from `size_hint` lower bounds. They reallocate and leave unwiped copies of passwords, OTPs, and revealed, copied or prefilled secrets in freed heap.
  - The 8192-character overwrite forces the edit buffer to grow, which can move it and leave the original text unwiped.
  - The lossy conversion also replaces lone surrogates with U+FFFD, silently altering pasted data.
- **Fix:**
  - Pre-size with `Zeroizing::new(String::with_capacity(n * 3))` and `Vec::with_capacity(len + 1)`, then push manually.
  - Decode strictly with `char::decode_utf16` and reject invalid input.
  - Overwrite edits with filler of the current length via `EM_SETSEL` + `EM_REPLACESEL`.

### 10. Low (hardening; needs a same-integrity sender) – `WM_COMMAND` handlers ignore the current screen
- **Where:** `App::command` and `modal_command`.
- **Scenario:**
  - `CANCEL` on Login switches to the Vault screen with no session.
  - `CREATE` while unlocked keeps the session decrypted on the Create screen with the 300 s idle limit.
  - `DELETE` while on Edit shifts indices, so `editing` points to a different entry and `SAVE` overwrites it.
- **Fix:**
  - Keep a per-`Screen` allow-list of command ids, and require `session.is_some()` for Vault, Edit and Password commands.
  - Stamp `editing` with a mutation generation counter and check it on `SAVE`.

### 11. Low – Original edit procedure is stored in cross-process-writable `GWLP_USERDATA`
- **Where:** `App::input` and `edit_proc`, which transmutes the stored value to `Proc` and calls it.
- **Scenario:** Another process can write `GWLP_USERDATA` (only `GWLP_WNDPROC` is restricted cross-process). `edit_proc` then calls that value. CFG limits the possible targets.
- **Fix:** Store the EDIT class procedure in a `static AtomicIsize`/`OnceLock`, or use `SetWindowSubclass`.

### 12. Low – Enrollment secret is painted before the environment check
- **Where:** `command` `CREATE` calls `check_environment` only when a session exists; `paint` then draws the setup code.
- **Scenario:** Under RDP, shadowing or a debugger, the TOTP seed is displayed for up to one 500 ms tick.
- **Fix:** Call `check_environment(self.hwnd)?` before `Provision::new()`.

### 13. Low – Incomplete session-change coverage
- **Where:** `window_proc`, which handles WTS events `{3, 4, 7}`.
- **Scenario:** Fast user switching or `tsdiscon` (2), logoff (6) and remote-control/shadowing (9) are not handled immediately.
- **Fix:** Add 2, 6 and 9, in both the handler and `security_event`.

### 14. Low – State and UX defects
- **Activity in dialogs:** Activity is only refreshed in the main loop, so browsing in the backup dialog for more than 60 s locks the vault and aborts the backup.
- **App switch during editing:** Switching apps on the Edit screen discards the unsaved entry. This conflicts with the documented "paste from another app" workflow.
- **Login password:[SECRET] A typed password on the Login screen is never cleared on idle.
- **Page index:** `page` is not reset on `REVEAL` or `EDIT`. After shortening a secret, the view shows "3 / 1" with a blank page.
- **Close hang:** On `WM_CLOSE`, the app waits forever if the clipboard can't be opened. Add a timeout.

### 15. Low – Path identity checks and leftover files
- **Weak `distinct`:** It compares lowercased strings. Hard links, alternate data streams (e.g. `vault.goyo:k`) and alternate mount paths all pass.
  - **Fix:** For existing files compare `(VolumeSerialNumber, FileIndex)`, and reject `:` in file names.
- **Leftover files:**
  - `.goyolock` sidecars are never deleted and reveal the vault, key and backup locations.
  - Temp files left by a crash hold old ciphertext.
- **Non-atomic replace:** On FAT/exFAT the replace is not crash-atomic, but the README claims atomic writes.

### 16. Info – Documentation contradiction
- `HashMap` uses `RandomState`, which makes std call `ProcessPrng` (Windows RNG).
- It is not used for secrets, but it contradicts the "no Windows RNG" claim.
- Use `BTreeMap` if the claim should hold.

### Optional hardening
- Link with `/CETCOMPAT`.
- Consider the `MicrosoftSignedOnly` signature policy after startup. Test it with IMEs and file dialogs; `ProhibitDynamicCode` may already crash some shell extensions.
- Call `DisableProcessWindowsGhosting`, since Argon2 blocks the UI thread.
- Add the `ExcludeClipboardContentFromMonitorProcessing` clipboard format.
- Exclude the process from WER dumps.
- Enable the `zeroize` features of `chacha20` and `poly1305`.

## Material residual limitations
- **Same-user code is not a boundary.** It can read memory, inject messages and hook the process. The debugger, affinity and message-filtering checks are all bypassable.
- **File dialogs load third-party code.** Shell extensions run in-process while the data key and entries are in memory.
- **Unwiped Win32 copies remain:**
  - edit-control heap
  - listbox titles, readable cross-process via `LB_GETTEXT` and MSAA because the listbox is not filtered
  - GDI text
  - freed clipboard memory
  - pagefile, hibernation file and crash dumps
- **Capture exclusion needs testing.** Verify it against `PrintWindow(PW_RENDERFULLCONTENT)` and `GetDC`/`BitBlt`. IME composition windows are separate top-level windows and are not covered.
- **OTP is an app gate only:**
  - The watermark is per file: a code used for restore can be replayed on the live vault within the window, and old backups allow rollback.
  - Backoff resets when the app restarts.
- **Password change does not revoke anything (documented).** Old key copies plus the old password decrypt every future save.
- **Default paths colocate the vault and key** in the executable's folder.
