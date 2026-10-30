# Security keys (experimental)

[한국어](SECURITY_KEY.md) · <b>English</b>

> [!WARNING]
> **Experimental: not verified with real security keys. Not in the default build or the release ZIP.**
>
> This feature was tested only with a fake security key (a test stand-in). What must still be checked on real keys is in the [real-key checklist](#real-key-checklist) at the end, and none of it has been run. **Do not use it for an important vault yet.** If you try it, practise first on a test vault filled with fake values.

## What it does

Turning security keys on locks the key file with **both the password and a registered security key** (a FIDO2 key such as a YubiKey). Opening the vault then needs the vault file, the key file, the password and a touch of one registered key (and the key's PIN, if PIN is on).

Unlike the OTP, the security key takes part in decryption. So even someone with both the key file and the password cannot open the vault without a registered key, and the key file alone gives no offline password guessing. It is another option, not a recommendation over the OTP, and the two can be used together.

Inside, there are two secrets:

- **The keyset secret**: 32 random bytes. Only a value that a registered security key gives (hmac-secret) can reach it. Every write of the key file makes a new one.
- **The data key**: the key that encrypts the vault. It needs the keyset secret **and** the password together.

> **If every registered security key is lost or reset, this vault can never be opened again.** Not with the password and the key file, not by its creator, not by the developer; there is no recovery code. Register 2 or more keys and keep a spare elsewhere. Write each key's number (security key 1, 2, …) on the physical key.

## Building the security-key build

The install ZIP (`python scripts/package_release.py`) is always the default build, without security keys. You build the security-key build yourself.

1. Get the source and make the default ZIP once as in the README's 'Install', so you have the `GoyoVault` folder.
2. In the same source folder, build the security-key build:
   ```powershell
   cargo build --release --locked --bins --features security-key
   ```
3. Check that `target\release\goyo-vault.exe --self-check | Out-Host` shows `security-key: EXPERIMENTAL build` and `salt self-test: PASS`. If Windows' WebAuthn is available it also shows `WebAuthn API <number>`.
4. Copy `target\release\goyo-vault.exe` and `goyo-sync.exe` over the files of the same name in the `GoyoVault` folder. Replace **both**: only the security-key build of goyo-sync does key-file sync. The folder's `SHA256SUMS.txt` (the hash list of the default build) then no longer matches these two files.

To go back to the default build, first use **Turn off keys** in the security-key build. The default build does not open a key file locked by a security key (see [What the default build does with a security-key file](#what-the-default-build-does-with-a-security-key-file)). Then, on **every other PC that uses this vault, while it still runs the security-key build**, take that change (carry the new key file of the PC that turned keys off by USB, 'Receive a new key file', type the key check code). Switch a PC to the default build only after it took the change. A PC that has not taken it still records this vault as a security-key vault, so both builds refuse a password-only key file there. The only way out is then to delete that PC's key record (`goyo-vault.keys`), which drops the record of every vault.

**Windows' `webauthn.dll`.** The security-key build loads `webauthn.dll` from System32 only when it opens a key file with security keys, or when you turn keys on or register one (there is no static import, and a vault without keys never loads it). That DLL then brings in the System32 DLLs it uses itself: at load combase, oleaut32, rpcrt4, windows.storage, advapi32, sechost, msvcrt, ntmarta; at the first calls cryptngc, winsta, bcryptprimitives; at the first touch dpapi, bcrypt, crypt32. The vault's cryptography never uses them. The window that asks for the touch and the PIN is Windows' own.

## Turning it on

**A new vault.** In 'Create', turn on **Security keys too (experimental)**. The key PIN is always used (see PIN below).

**A vault you already use.** In 'Key management', check **Also change the password (recommended)**, enter the current password (and OTP), and press **Turn on security keys**. The data key changes too.

- **Why change the password too:** the key files made before keys were on, and their backups (the 0.8 key file, a `GOYOKE03` from an earlier password change), open with the password alone. If you keep the password, whoever finds such a copy can keep guessing that password offline, and once they guess it only a registered key (and its PIN) is left. If you keep the password, delete those old copies.
- **Registration:** each key opens three Windows windows (one registration, two checks). Touch the same key each time and enter its PIN. For a key without a PIN, Windows has you set one in the first window.
- **NFC:** unplug a key you will hold to an NFC reader **before** the Windows window opens. If it is plugged into USB when the window opens, Windows uses that connection and the reader gets no answer. Over NFC too, type the PIN on screen first, then hold the key to the reader.
- **Register 2 or more, together, on one PC.** Keys registered together **pair** with each other (below). With only one key, every unlock shows a red warning.
- **Give every key its own PIN.** With one PIN on every key, whoever holds a lost key and its PIN can clone another key just by getting hold of it briefly.
- **Write the key number on each key.** The app calls them only 'security key 1, 2, …'.
- After registering, make a **Back up key**. If the key file is lost, the vault does not open even with the security keys and the password.

**Room on the security key.** Each registration uses one 'discoverable credential' slot on the key (a YubiKey 5 has about 25 or 100, depending on its firmware). When they are full, new registrations fail; delete the entries of removed keys or failed registrations with the key vendor's tool (for a YubiKey `ykman fido credentials delete`, on Windows from an administrator prompt; it needs the key's PIN). Entries are named `Goyo Vault <first 8 of the vault ID> key <number> <registration time>`, and only an entry whose time matches the 'label' shown in Key management belongs to this vault. Windows Settings' passkey list is for passkeys saved on the PC and is expected not to show entries on a security key (not verified).

## PIN

- **The PIN is always used.** There is no choice to turn it off. A registration that stores an entry on the key makes Windows have you set a PIN on a key without one, and once a key has a PIN Windows asks for it every time, even when the app does not require it (checked on a real key). So a no-PIN mode cannot hold on Windows. Every registration requires the PIN (user verification required) and PIN-required protection (credProtect 3, required), and key files are always written in PIN mode.
- The key's PIN is typed into the **Windows Security window**. It is another process, so Goyo Vault's screen-capture blocking does not cover it.
- Eight wrong PINs lock the key. A FIDO reset of a locked key removes its registration, so it can no longer open this vault.
- A key file a pre-release test build wrote without the PIN (the feature never shipped that way) still opens and changes as before. Keys added to it are registered with the PIN, and key-file sync can be turned on only for a PIN-mode file whose keys were all registered with a PIN. Turning security keys off and on again makes such a vault PIN-mode.

## Opening and 'Key management'

The login screen says the key file needs a security key (and how many are registered); pressing 'Unlock' opens the Windows Security window. Plug in any registered key, enter its PIN and touch it (unplug a key you will hold to an NFC reader first). The Windows window always belongs to Goyo Vault's window. Called with no owner window, Windows refuses at once (0x80090027), and the app then says "Windows rejected the security key request".

The lower part of 'Key management' is the security-key section:

- The state line: `Security keys: on · PIN used · 4 registered`.
- **Keys that can stand in for all the others:** keys paired with every other key. When a key is lost, any one of these removes it at once. If it says none, use **Pair keys**.
- The key list: for each key its registration date, whether it opened this unlock, its label (the time in the key's entry name) and its pairing state ('paired with every key', 'needs pairing with security key 4', 'suspended (needs pairing)', 'possibly cloned', and so on).
- The buttons: **Add key**, **Pair keys…**, **Re-lock all keys…**, **Remove a lost key…**, **Remove keys…**, **Turn off keys**. The current password (and OTP) in the fields below is what every button checks again.
- The **key check code** (`E5 · XXXX-XXXX-XXXX-XXXX`): another PC types it to take an added key or a settings change from this PC. Only the current data key computes it, so not even the holder of a lost key can produce it.

## Pairing

Keys touched together at one place **pair** with each other. Paired keys can pass a new key on for each other. So with one key paired with all the others, a password change, adding a key and removing a key each take **that one key and one touch**, and no key has to be carried anywhere.

- **Register every key together on one PC at the start.** Then every key is paired with every other.
- **A key bought later** is added with one key at hand (one touch of that key plus three for the new key's registration). The new key opens the vault at once. Any other key plugged in at that place can be touched too and pairs with it.
- **With the keys at another place**, take the new key there once, later, when convenient, and use **Pair keys** (one touch per key it meets). Until then it cannot stand in for the keys it has not met, and removing a key at that place may **suspend** it.
- **Suspended:** a key that the touched key cannot pass the new key to, because the two are not paired. It happens only in a removal or a join, and only after the app names it and you agree. A suspended key does not open the vault; it comes back as soon as a key paired with it writes anything, or through **Pair keys**.
- If a pairing record is damaged ('pairing record damaged' in the list), pair the two keys again at one place.

## When a key is lost

**In one line: run 'Remove a lost key' on the PC at hand, then on every other PC that uses this vault either take that change or run the same removal.**

### On the PC at hand

1. 'Key management' › **Remove a lost key…**
2. Pick **every** lost key.
3. **Roughly when was it lost?** Leave it empty if you do not know (the review list below then shows the whole record).
4. **Could someone else know the PIN or the password?** 'Yes' if someone saw it, it was written down with the key, or you use it elsewhere too. With 'Yes' or 'Not sure':
   - it asks for the other keys that share that PIN; those are marked 'possibly cloned';
   - **Change the password too (recommended)** is turned on. Choose a new password. A key file made by whoever holds the lost key then does not open with the new password. In a vault with key-file sync, another PC opened with the new password opens through the server's new key file, so if the server hides this change, the new password works nowhere and that shows it (see [The limit of a freeze](#the-limit-of-a-freeze)).
5. Check 'Key to touch' on the right, enter the current password (and OTP), press **Remove** and touch one staying key.

**One touch, and this PC is protected from that moment.** A new keyset secret and a new data key are made, and the lost key gets nothing of them. No key has to be carried to another place. A key never authorizes its own removal, so a key file made with the lost key cannot remove that key.

- If a key is not paired with the key you touch, the app names it and asks before **suspending** it. If that key is at hand, press 'Touch that key too'.
- A key that was paired only with the lost key (for example a spare added with it) is offered for removal too (recommended). Keep it if it may be another place's only key.

### On every other PC

**No design can make a removal reach another PC with no action there.** Until you act on that PC, a server that hides the change (a freeze) keeps that PC open to whoever holds the lost key with its PIN and the password. On every other PC, do one of these:

- **Take the change.** Before taking it, that PC asks you to **pick the lost keys**, and shows nothing about the change before you pick. It passes only if your pick matches the removed keys exactly (see [The gate on other PCs](#the-gate-on-other-pcs)). A wrong pick cannot be retried; then only typing the key check code shown on the first PC is left.
  - **A vault with key-file sync:** it is taken when you open that PC. If the password was changed at the removal, open with the **new password**: that PC's own key file does not open with it, so it asks "Try the server's new key file?"; answer Yes and pick the lost keys, and the same touch takes it and opens. Opened with the old password, it asks for the lost keys right after the unlock and for the new password while taking it. If you pressed 'Later', take it with **Get…** in 'Key management'.
  - **A vault whose key file stays on the PCs:** carry the first PC's new key file by USB and take it with 'Key management' › **Receive a new key file…**, then pick the lost keys. One carry is enough.
- **Remove it on that PC too.** If that PC must be protected right now (you cannot carry the file, or you do not trust the server), run **Remove a lost key** there as well. That PC is protected at once. The two PCs' key files now diverge and are joined later:
  - with key-file sync, when both PCs only removed keys from the same state, the PC whose upload came second joins them by itself at its next unlock ('While it is on' below). If one side also changed the password, that PC's 'Key management' shows that it split from the server's key file and to join it with [Get…]; press **Get…**;
  - with the key file on the PCs only, sync resumes once each PC has taken the other's key file once with 'Receive a new key file'.

### Afterwards

- **Review what came in by sync.** When the removal of a lost key lands on a PC (made there or taken), it lists the changes that came in by sync from other PCs since the day before the loss. Whoever holds the lost key may have slipped changes in through the server, so check entries that are dangerous when changed (account numbers, wallet addresses, recovery e-mails, login addresses) and press **Reviewed**. Until then this PC does not upload its vault contents (the key file still goes up), and the list comes back at every unlock. The list covers only what the security-key build merged on this PC, is not an authenticated record, and helps only with a realistic date.
- **Keys that shared the PIN** ('possibly cloned'): when every key is at one place, use **Re-lock all keys**, or remove that key and register it again. If a security key may have been in someone else's hands, do not only change the password: use 'Re-lock all keys', or remove the key and register it again.
- **What was saved before is not protected.** Removing or replacing keys protects only what is saved afterwards. Everything saved before stays readable to whoever has the lost key with its PIN, the password and an old key-file copy (with key-file sync: the server's history). If that may be the case, change the secrets themselves (the real passwords and keys, where the funds are).
- **Removing old history on the server.** In a vault with key-file sync, the removal asks whether to delete the vault history from before the change (the last 200 versions) on the server. That only matters with an honest server; assume a hacked server has already copied it.
- **Clean up keys you no longer use**: see [Removing keys and keys you no longer use](#removing-keys-and-keys-you-no-longer-use).

### Every key of one place lost

That place's PC cannot unlock until a key gets there, whatever the design. The removal itself is one touch at the other place.

1. On the other place's PC, **Remove a lost key**, pick every lost key and touch one staying key.
2. On the same PC, with that place's keys plugged in, register a new key with **Add key** (it pairs with them at once, so no later pairing visit is needed).
3. Carry **the new key together with that PC's new key file**, and note that PC's key check code. With key-file sync there is no need to carry the key file: on the PC that lost its keys press 'Unlock' as usual and cancel Windows' security window (which looks for a key that PC knows); it then asks "…try it?" for a key only the server's key file lists. Press [Touch], touch the new key and type the noted code: it opens and takes the new key file too.
4. If you carried the key file, choose it at login on the PC that lost its keys and open with the new key. The key file holds a key that PC has never seen (the new key), so it asks for a key check code: type the one you noted. That PC's own key file does not list the new key, so it cannot open with it, and 'Receive a new key file' works only on an open vault.

## Example: 4 keys, 2 places

At home (A) are PC_A and security keys 1 and 2; at the office (B) are PC_B and security keys 3 and 4; both PCs sync this vault.

**Setup.** Register all four keys together on one PC (three Windows windows per key, 12 in all). Every key is paired with every other. Make a key backup, and carry the key file to the other PC by USB (that PC asks for this PC's key check code the first time it opens). Keep keys 1 and 2 at home, 3 and 4 at the office.

**Key 1 lost at home.**
1. PC_A: **Remove a lost key** → security key 1 → the date → "Could someone else know the PIN or the password?" **Not sure** (the password change turns on; choose a new password) → the current password → **one touch of key 2**. PC_A is protected from this moment. No key is carried.
2. PC_B with key-file sync: open with key 3 (or 4). Opened with the **new password**, answer Yes to "Try the server's new key file?"; opened with the old one, it asks right after the unlock. Pick security key 1 (nothing is shown before) and the unlock's own touch takes it (opened with the old password, type the new one while taking it). There is no second touch. Only if you pressed 'Later', take it with **Get…** in 'Key management'. Afterwards both PCs show the same key check code, and the review of what came in by sync appears.
3. PC_B with the key file on the PCs only: PC_B says "Another PC changed this vault's key, so sync stopped…" and stops syncing. Bring PC_A's new key file by USB → **Receive a new key file** → pick security key 1 → touch key 3 → the new password. If PC_B must be protected before that, run **Remove a lost key** on PC_B too (security key 1, touch key 3), and later each PC takes the other's key file once.

**Totals.** Keys carried: 0. At home: 1 touch. At the office: the normal unlock, plus one pick (with key-file sync the unlock's touch is enough; carried by USB, one more touch).

**A spare key 5 added at home later.**
1. PC_A: **Add key**, one touch of key 2 + three for registering key 5. Key 5 opens the vault at once. The list says key 5 needs pairing with keys 3 and 4.
2. PC_B takes this addition by typing PC_A's key check code (a photo of the screen helps). With key-file sync it is asked for the code at its next unlock (after 'Later', **Get…** in 'Key management'); otherwise carry PC_A's new key file by USB and use **Receive a new key file** (until then PC_B stops syncing). An addition is taken only with the code, never with a pick.
3. When convenient, take key 5 to the office once and, on PC_B, **Pair keys** with keys 5, 3 and 4 (3 touches). PC_A takes that pairing write without a question: with key-file sync at its next unlock, otherwise by carrying PC_B's key file by USB and using **Receive a new key file** (a pairing write changes the key file too, so until then PC_A stops syncing).
4. Before that visit: a password change at the office with key 3 cannot pass the new key on to key 5, so it asks for a touch of key 5 too (without key 5, cancel and do it at home with key 2). A removal made at the office suspends key 5 after asking.

**A second loss before the pairing visit** can leave key 5 on its own, so do not put the visit off too long.

## The gate on other PCs

A key file in which another PC changed the security keys (added or removed one) or a setting (PIN, key-file sync, keys off) is taken by this PC **only after you confirm it**. Until then this PC uploads nothing and does not merge server copies. If the key file itself had changed at login (a key USB stick several PCs share), entries cannot be edited or saved until then either.

- **A change that only removes keys:** "A security key was removed on another PC. Nothing about the change is shown until you pick on this PC. Pick every key that was lost or removed." It passes only if the pick matches the removed keys **exactly**. After one wrong pick that change cannot be picked again; only the code is left. A change made by whoever holds the lost key cannot remove that very key, so when you pick it, a forged change does not pass.
- **An added key, a settings change, the removal of a key this PC has never seen, a new PC, a key file carried by USB:** type the **key check code** that the changing PC's 'Key management' shows now (`E{revision} · XXXX-XXXX-XXXX-XXXX`). The changing PC shows this code in a dialog right after the change ("Other PCs need this code to take this change. Take a photo of it with your phone."), and 'Key management' keeps showing it. A wrong code stays in its field on the other PC, so it can be corrected. If its revision differs, that PC changed the key again in the meantime.
- **Later** puts it off; **Get…** in 'Key management' asks again.
- **Don't take…** only when you are sure the change is forged. If it was real, this PC stays stopped (you can still take it by USB later).
- If the PC that made a change that needs the code can no longer be used, so its code cannot be read (a dead disk, say), a vault with key-file sync offers **Upload this PC's state, no other PC…** in 'Key management': it uploads this PC's key file again at a higher revision than that change (a danger question, default No, the password and one touch). The change (for example a key added on that PC) is lost, so make it again if needed. The button is not offered for a change that removes one of this PC's keys, or that carries the removal of a key this PC never knew; then run 'Remove a lost key' or turn key-file sync off. The last vault copy that PC uploaded is overwritten with this PC's state. On a PC that kept its key file on this PC only, this turns key-file sync on there too, and that consent is asked first.
- With no other PC to check against (a new PC and every other PC gone), **Accept without a code (trust this server)…** (for a key file carried by USB, **Trust this key file without a code…**) lets you trust it after a danger question (default No), but there is no way to check that it is genuine. If the password was changed at the removal, a forged key file does not open with the new password.

## Removing keys and keys you no longer use

- **Remove keys…** removes keys that were not lost (broken, replaced). One touch of a staying key and it is done; the data key changes. No review list follows. The password change is optional.
- **On a key you no longer use, delete this vault's registration.** Otherwise that key, an old key-file copy and the password open old contents. To delete one registration use the key vendor's tool (for a YubiKey `ykman fido credentials delete`, on Windows from an administrator prompt; it needs the key's PIN). A key without a PIN needs one set first, and if another Goyo vault uses that key without a PIN, that vault may stop opening once the PIN is set.
- **A FIDO reset** only for a key you use nowhere else (another Goyo vault, website passkeys). A reset deletes every passkey on the key and other vaults' registrations, and if the key was another vault's only key, that vault can never be opened again.

## Re-lock all keys

For when someone may have known a PIN and briefly touched the security key (a suspected clone). Every registered key must be at one place; each is touched, then one more touch confirms. It renews each key's value, the pairing records, the keyset secret and the data key, so a key answer obtained before opens none of the later key files. Other PCs take it by typing the key check code. If the password may also be known, change it afterwards too.

## Turning keys off

**Turn off keys** changes the data key and writes a key file that opens with the password and the key file alone (`GOYOKE03`; weaker). The removed keys stay recorded in the key file, so turning keys on again later never brings an old key back. Other PCs take this change by typing the code. If the vault used key-file sync, that turns off too (below), and other PCs need the key file by USB. Clean up keys you no longer use as above.

## This PC's records

- **This PC's key record** (`%LOCALAPPDATA%\GoyoVault\goyo-vault.keys`, 'This PC's key record' in the README) is **required** for security-key vaults. It remembers that this PC opened the vault with security keys, the state this PC confirmed, waiting gates, reviews and 'possibly cloned' marks. It holds no secret and is not authenticated.
- If this record keeps the right key file from opening (a diverged file, a missing removal record, …), the security-key build offers **Forget this vault's record and confirm again…** on the login screen (and in 'Key management' while a gate waits) instead of deleting the whole file. After the password and a touch have opened it, it forgets only this vault's record and checks that key file again as one it has never seen (type another PC's key check code). Do not press it if the key file may be old or forged. Deleting the whole file drops every other vault's record and waiting gates too (a due review stays, thanks to the record below).
- **The merge log** (`%LOCALAPPDATA%\GoyoVault\goyo-vault.merges\<vault ID>.log`): in a vault that uses security keys and sync, one line per change that came in by sync, with only the entry ID and the time (no title, no content). The review list reads it. It is per PC, never synced, and whoever can write that folder can delete lines.

## Key-file sync (optional, experimental)

A per-vault option of the security-key build. It is off by default; when on, the key file also travels between PCs through the server, so a password change or a key removal no longer needs a USB carry. **In exchange, to anyone with access to the server the key file is no longer a separately guarded factor.**

|Mode|Build|What the server holds|Who can decrypt with the server's data|
|---|---|---|---|
|1. No security keys|default|vault ciphertext only|nobody (the key file never leaves the PCs)|
|2. Security keys, key file on the PCs only|security-key build|vault ciphertext only|nobody (the key file never leaves the PCs)|
|3. Security keys + key-file sync|security-key build|vault ciphertext **and** every security-key key file uploaded. Assume a hacked server keeps them all.|whoever has **the password and a registered security key with its PIN**. To anyone with the server or any PC's sync SSH key, the key file is no longer a separate factor. Old key files stay on a hacked server for good, so a removed key and the old password open the history up to that key's removal.|

**Assume a hacked server keeps everything ever uploaded.**

### What you accept (14 points)

1. The promise changes: 'the server only ever holds ciphertext it can never open' becomes 'the server cannot open it without both the password and a registered security key with its PIN'.
2. If the server or a sync SSH key is compromised, the attacker's only remaining barriers are the password and the security key + PIN. The key file stops being a third barrier.
3. A key file once uploaded can be kept by whoever had server access at that time. Removing a key or changing the password protects only what is saved afterwards. If a security key was lost and the password may be known, change the secrets themselves (move funds, reissue keys).
4. After a key removal, the removal is complete only once every PC has taken it (by picking the lost key or typing the code). The same key check code on two PCs means the same key state.
5. A new PC must type another PC's key check code before first use. Carrying the first copy by USB is recommended; starting from the server works too (see 'A new PC' below).
6. The server copy is not a backup. A USB key-file backup and 2 or more security keys stay mandatory. There is no recovery code.
7. The PIN is mandatory. Use 6 or more characters, different from the password. Eight wrong tries lock the key, and a reset key can no longer open this vault.
8. On a key you no longer use, delete this vault's registration (a FIDO reset only for a key used nowhere else). Otherwise, with the password, it opens the old key files left on the server.
9. If a PC is lost, delete that PC's `authorized_keys` line at once. Use one server account per person: another sync key of the same account can fetch your key file too.
10. A key-file copy sits in each PC's sync folder (`incoming.goyokeysync`). That weakens the separation of keeping the key file on a USB stick only.
11. Phone passkeys and Windows Hello cannot be used. Only USB or NFC security keys.
12. After a key change the other PCs take it at their next unlock (or later with [Get…] in 'Key management'): a removal by picking the lost key, an added key or a settings change by typing the changing PC's code. Nothing about the change is shown before.
13. Turning security keys off, or key-file sync off, means the other PCs need the key file by USB again.
14. The gain: no USB carry after a change. Only with an honest server, though; when the server is attacked, sync stops (no data is lost).

### Preparing the server

1. Update the server script to 0.9.0 ('Install or update on server' in goyo-sync's window).
2. Find the vault ID (32 lower-case hex digits): the second column of `goyo-sync.exe --list | Out-Host`.
3. In the dedicated-key line of **every PC** that uses that vault ([SYNC.en.md](SYNC.en.md), 'Dedicated key with a forced command'), add `--key-sync=<vault ID>` after `serve`. For several vaults, join the IDs with commas (up to 64, no spaces). The settings window of the security-key build's goyo-sync writes this line: **Forced command line…** under the vault list shows the line with that PC's Python command, script path and, by themselves, the IDs of the listed vaults that use key-file sync (the vault file or the server's latest copy was saved with a `GOYOKS01` key file, Goyo Vault left a key request, the server holds the key file, or the state is `nokeys`); Ctrl+C copies it, and you fill in the public key yourself. None of this is saved, and the settings window has no key-file sync switch (it is turned on and off in Goyo Vault's 'Key management' only). A vault not turned on yet is not in the line, so to add it before turning it on, append its ID by hand. If it was added after turning it on, 'Key management' shows 'The server does not take key-file sync for this vault' until the line is changed; goyo-sync then checks again within two minutes.
   ```
   restrict,command="/usr/bin/python3 -I /home/<user>/.local/share/goyo-sync/goyo-sync-server.py serve --key-sync=0123456789abcdef0123456789abcdef" ssh-ed25519 AAAA… goyo-sync-pc1
   ```
   - Use a separate dedicated key per PC; if one PC is lost, delete only its line.
   - One wrong character (upper case, 31 digits, an empty `--key-sync`) makes the server refuse **every** request of that line, and the helper shows `server`.
   - Add it **just before** turning key-file sync on, and remove it from every line once turning it off has finished and every PC has taken that. A vault named on a line keeps a key-record floor on the server in every mode, so whoever steals that line's sync key can block every PC's uploads (until the admin deletes `data/<vault ID>/k/`).
4. The server's data folder (`~/.local/share/goyo-sync/data`) must support `flock`. Every common local Linux file system does, and NFS emulates it. The selftest at install checks the lock in that folder.
5. Delete `data/<vault ID>/k/` **only while no PC syncs that vault**.

### Turning it on

- Conditions: security keys on in PIN mode with every key registered with a PIN; sync on for that vault; this Windows reports how the key is connected (USB/NFC); the security-key build's goyo-sync checked the server within the last 10 minutes; the server holds no key file of this vault yet (if another PC turned it on, take that file with [Get…]).
- 'Key management' › **Turn key-file sync on…** → a danger question (default No) that shortens the 14 points to 10 → the password and one touch. The key file is written again (the data key stays) and goyo-sync uploads it.
- This one button in Goyo Vault is the only switch. The line beside it says where this vault's key file lives: **Key file: kept on this PC only (other PCs get it by USB)** or **Key file: synced through the server (experimental)**.
- Other PCs take this change by typing this PC's key check code, and see the same explanation of the risks.
- On a vault with key-file sync, the PC that changed the keys (on, a key added or removed, a pairing, re-locking every key, a password change, uploading this PC's state) says at every unlock, in the status line, "Not yet confirmed that the other PCs took this key change…" ("…this removal…" in red for a removal), and the top of the list in 'Key management' says what each other PC must do to take it (a removal: pick the removed keys, or type this PC's code on a PC that never knew a removed key; a key added or every key re-locked: type this PC's code; on, a re-upload or uploading this PC's state: the next unlock, and a PC that kept its key file to itself types the code; a password change or a pairing: the next unlock). Once every PC took it, press **All PCs confirmed** in 'Key management'. Until then the change is not complete. This reminder lives only in this PC's key record and is not protected cryptographically.

### While it is on

- After a key change, the other PCs take it **when they unlock**. A change that needs no gate (a password change, say) is taken with the unlock's own touch; one that needs a gate asks for the lost keys or the code right after the unlock. Opening with the **new password** set on another PC works too: this PC's own key file does not open with it, so it asks "Try the server's new key file?", and Yes takes the server's key file with the same touch and opens. If it was not taken then, 'Key management' says a new key file, or a key change to confirm, is on the server; take it with **Get…** (the gate above). While it waits, that PC neither uploads nor merges.
- If you only have a key newly registered on another PC, cancel Windows' security window at 'Unlock'. When the server's key file lists that key, it asks "…try it?"; touch the new key and type that PC's code to take it and open.
- If two PCs change the key at once, it says the key file split from the server's and sync stops. Join them on one PC with **Get…** (**Use the other PC's** or **Join both**). If nothing like that happened, the server copy may be forged.
- When two PCs **only removed keys** from the same state (the same lost key removed on each PC), they join by themselves. The PC whose upload came second opens the other PC's key file at its next unlock with that unlock's touch and password and, asking nothing, writes a key file that joins both (a new data key). The status line says "Merged the key removals made apart on two PCs…", and the PC that uploaded first takes the result at its next unlock with no confirmation. If one side also changed the password, or this PC's key is out of that key file, it cannot be opened without a question, so it is not joined by itself; when "…they can be merged with [Get…]" shows, join them with **Get…** (it asks for the other password or another key). If that key file does not open with this PC's security key and password, nothing is written, it is refused as "a forged link", and it is not tried again until Goyo Vault restarts.
- While the server refuses this PC's key file, this PC's vault does not go up either (goyo-sync state `keyfile` or `refused`). Bring goyo-sync and the server script to the same version.
- If the server no longer has this vault's key file ('Key file: synced through the server (experimental) · not on the server'), another PC may have turned it off. Then do not upload it again; take that PC's key file by USB. Press **Upload the key file again** only when you are sure nobody turned it off and it was deleted. Until then this PC neither merges nor uploads server copies.
- If the PC that made a waiting change is gone, use **Upload this PC's state, no other PC…** (see 'The gate on other PCs' above). For a change with no such button (one that removes a key of this PC, say), run 'Remove a lost key' or turn key-file sync off. End it with **Don't take…** only when you are sure the change is forged.

### A new PC

Recommended: carry the key file to a new PC **by USB** the first time. The first time it opens, that key file is new to it, so type another PC's key check code.

**Starting from the server** (the same for a PC that lost its key file):

1. In the security-key build's goyo-sync settings window press **Bring to this PC…** and pick the vault and the folder to save it in. The vault file is saved in that folder as `vault.goyo`; when the server holds this vault's key file, it goes only into the sync folder next to it (`vault.goyo.sync\incoming.goyokeysync`). No key file (`.goyokey`) is made. The vault is added to goyo-sync's sync list as well.
2. Open Goyo Vault. If that folder is Goyo Vault's own folder it opens right away; otherwise choose that `vault.goyo` with **Open a vault from another location** on the start screen (or **Browse** on the login screen). The **Vault brought from the server** screen says what happened and lists the three steps left. Type the password (and the OTP if the vault uses one), press **Next · touch the security key** and touch your security key (when the server's key file has no security keys, the button reads **Next** and nothing is touched). A vault this PC opened before, picked while its key file is there (on a USB drive, say), opens on the usual login instead.
3. The opened vault is read-only for now. In **Confirm the key file from the server** on the right, type the key check code another PC's 'Key management' shows now (shaped like `E7 · 1A2B-3C4D-5E6F-7A8B`) and press **Check code**. Until then no entry can be edited, and neither the key file nor the vault file is saved on this PC. A wrong code is reported in a dialog and stays in the field, so you can correct it. Until this step is done, **Back up vault**, **Back up key** and **Key management** below are greyed out. With no other PC to check against, **Accept without a code (trust this server)…** shows its danger warning and then the save step, which then says "You chose to trust this server without a code" (never that the file was checked).
4. Once the code matches, "The key file is saved next to the vault" appears. **Save here** saves it next to the vault as `vault.goyokey`; **Save elsewhere…** saves it where you choose (outside the sync folder, never over an existing file). It then writes the key file, the vault file in its place and this PC's key record, in that order. From then on the vault opens as usual. Lock now and open it again to start syncing with the server on this PC. If that is cut short:
   - If the key file exists already, open it at the login screen as usual. Opening it finishes this PC's key record.
   - Otherwise opening Goyo Vault again shows the same screen. It does not ask for the code again; only **Save** is left. Save the key file under **the same name** as before: a key file written there before the cut is used as it is (if its content differs at all, it is not overwritten and you are asked for another name).
5. If this PC still has the vault file (only the key file was lost), that vault file is the floor: a server key file older than it is not opened. Nor is a key file that does not match this PC's record of the keys (a split or an older one).

When the server has no key file for this vault (a vault that keeps its key file on each PC), put the other PC's key file into the same folder by USB as `vault.goyokey` and open as usual. That key file is new to this PC, so the same code field appears. **Restore from backup** is only for backup files made with 'Back up vault'.

With no other PC, trusting it is the only option ('Accept without a code (trust this server)…' above). Use **Back up key** after saving.

### Turning it off

'Key management' › **Turn key-file sync off…** (**Turn off keys** turns key-file sync off too):

1. This PC asks the server to delete the key file, changes the data key and writes a key file that cannot be uploaded (`GOYOKH01` for key-file sync off, `GOYOKE03` for keys off). From then on this PC uploads no key file.
2. The deletion reaches the server when the security-key build's goyo-sync runs. 'Key management' shows the deletion as pending, then once 'the server answered that it deleted it (record N)'. It never says 'done': a hacked server may not have deleted anything.
3. Turning it off ends the server's **whole current key-file record** for this vault. Another PC's change that this PC has not taken yet (for example a password change) that landed in the meantime is deleted from the server too; exchange key files with that PC by USB once each way. A warning before turning it off, "The server has a key file this PC has not taken (revision N)…", means exactly that.
4. Other PCs stop syncing and need this key file by USB ('Receive a new key file', with the code). Do not undo it by uploading again from another PC; decide about that PC's own setting while taking the file by USB.
5. If you will not turn it on again, remove this vault's ID from the `--key-sync` list of every PC's forced command once every PC has taken the change.
6. If the off is cut short (a power cut, …) before the new key file is written, the next unlock undoes it (nothing changed, and no deletion request is sent). Turn it off again. If it is cut short after the new key file was written, the next unlock finishes the off.

### When a PC is lost

Delete that PC's `authorized_keys` line **at once**. That PC's sync key can fetch the key file, block uploads and end the key-file record (sync stops; a forged key file is never accepted). If it damaged the record, the admin may need to delete `data/<vault ID>/k/` (while no PC syncs that vault). If security keys registered there were lost with it, follow 'When a key is lost' above.

### The limit of a freeze

If the server keeps hiding a key change from a PC (a freeze), that PC stays in the old state until you act there. Meanwhile whoever holds the lost key, its PIN and the password can read what that PC saves and slip changes in through the server. Key changes they make stop at the gate. The way out is **Remove a lost key** on that PC.

**How to notice it.** If the password was changed at the removal, open the other PC with the **new password**. If the server is hiding the change, the new password does not open it and "Try the server's new key file?" does not appear either; then open with the old password and run **Remove a lost key** there. If the password was not changed, open the other PC after the removal and give sync time to run once. If none of the notices below appears, the server may be hiding the change: run **Remove a lost key** on that PC too.

- A vault with key-file sync: "A key file in which another PC changed the security keys or a setting is on the server…", or "A key change to confirm is on the server" in 'Key management'.
- A vault whose key file is on the PCs only: "Another PC changed this vault's key, so sync stopped…".

## Remaining risks

- **Only partly verified with real keys.** That a key's answer is the same at every touch and over USB and NFC, credProtect 3, two salt values in one touch and an allow list of two keys were checked on a YubiKey 5C NFC. Whether the answer stays the same across reboots, PIN changes and months, whether a lookup without the PIN really fails, whether phones and Windows Hello are refused, and more, are confirmed only once the 'not run' items of the checklist below pass.
- **A key answer obtained once lasts.** Whoever briefly had the key with its PIN and touched it has, in effect, a clone until that key is removed or 'Re-lock all keys' runs. Such a clone can pass the 'pick the lost keys' gate too; only typing the code stops it. Give every key its own PIN.
- **Freeze** (above). No design avoids it.
- **A new PC or a disaster recovery with no other PC to check against** can only trust.
- **Old history.** Everything saved before a key's removal can be read by whoever has that key with its PIN, the password and an old key file. With key-file sync, the server's old key files are such copies.
- **User error.** Picking fewer keys than were lost can let a change made by holders of two lost keys pass. So can a code read from the wrong screen. Pick **every** lost key.
- **A spare before its pairing visit** cannot stand in for the keys it has not met, and a second loss in the meantime can leave it on its own.
- **Before you notice.** Until the loss is noticed, whoever holds the key (with its PIN and the password) is a full member. The review list helps only with a realistic date.
- **Denial of service and prompt fatigue.** The server can stop sync, split key files or keep changes waiting at a gate. No data is lost.
- **This PC's records are not authenticated.** Code running as the same user can change or delete them.
- **The request files in the sync folder are not authenticated either.** Someone who can write that folder (a shared folder, a NAS) can make that PC's helper end the server's key-file record or delete old vault history (it disrupts sync; it never makes a forged key file accepted).
- **What the server sees.** In every mode: the vault file header (key ID, revision, state tag, whether security keys and key-file sync are used), so how many key changes there were and roughly when. With key-file sync, also the whole key file: change kinds, the authorizing key's number, the numbers of keys, removal records and pairing records, registration times, credential IDs, change times and a reported loss date.
- **Windows.** The PIN window is outside screen-capture blocking, and the PIN and the key's answer pass through Windows, whose buffers cannot be wiped.

The detailed threat analysis is in [SECURITY_REVIEW.md](SECURITY_REVIEW.md) ('0.9.0 change: security keys (experimental) and key-file sync (experimental)', in Korean), the file formats in [FORMAT.md](FORMAT.md) (Korean).

## What the default build does with a security-key file

The `goyo-vault.exe` of the release ZIP does not open a key file locked by a security key (one whose first 8 bytes start with `GOYOKH` or `GOYOKS`). As soon as you choose such a file, and when you press 'Open' or 'Restore', it looks at the first 8 bytes only, before checking any password, and says "This key file opens only with a security key (YubiKey or similar)…". It never says the password is wrong, does not count a failed attempt and starts no retry delay. If the file is cut short, or a newer version made it so that it fails the format check, it adds "The file may also be damaged, or made by a newer version." The default build cannot tell whether such a file is damaged, so it never replaces it with a temp file (`.goyotmp`) left by an interrupted save either. A vault file saved under a security-key file, opened with a key file that lacks its key, gets "This vault file was saved with a key file locked by a security key…" and is not opened. Opening any of these files needs a build with the security-key feature.

If a received key file is refused as "an unexplained change" (another PC set the password back to one this PC still uses), change this PC's password first. The file then counts as diverged, and 'Receive a new key file' joins the two.

## Real-key checklist

Before security keys can be on by default, or key-file sync can leave 'experimental', all of the following must pass on real keys. Any failure keeps the feature off by default. If Windows cannot enforce the PIN, USB/NFC only and the raw key answer, key-file sync is not offered at all.

**Result: partly run.** Every 'passed' below was checked on a **YubiKey 5C NFC, Windows 11 26200, API 9** (six keys, an HID OMNIKEY 5022 NFC reader). The rest was not run. What the checks changed: security keys always use the PIN (PIN above), every Windows call names Goyo Vault's window as its owner (owner 0 fails at once with 0x80090027), and a key used over NFC is unplugged before the window opens.

|#|Check|Result|
|---|---|---|
|1|hmac-secret really comes back through webauthn.dll (API 9), is 32 bytes, and stays the same across unlocks, reboots, PIN changes and months (YubiKey 5 firmware 5.2-5.6 and 5.7+)|partly passed: the 32-byte value for one salt is the same at every touch, and the same over USB and NFC (verified on YubiKey 5C NFC, Windows 11 26200, API 9); unlocks, reboots, PIN changes, months and firmware versions not run|
|2|Whether Windows ignores hmac-secret for non-discoverable credentials (register with resident key on and off, then GetAssertion)|not run|
|3|`HMAC_SECRET_VALUES_FLAG` is honored, so both computations agree for Goyo's PRF input (API 9; 4-8 if possible)|passed: the flag with SHA-256("WebAuthn PRF\0"‖s) gives the value of s without the flag (verified on YubiKey 5C NFC, Windows 11 26200, API 9); API 4-8 not run|
|4|The WebAuthn API version on Windows 11 builds 22000, 22621, 22631, 26100 (only 26200 = API 9 was measured)|not run|
|5|RP ID `goyo-vault.invalid` is accepted; how it shows in the Windows window and in ykman's list; whether Windows Settings' passkey list shows security-key entries|partly passed: the RP ID is accepted (verified on YubiKey 5C NFC, Windows 11 26200, API 9); how it shows in the window, in ykman and in Windows Settings not run|
|6|Behavior with uv=discouraged on a key with a PIN, after setting a PIN later, with alwaysUv, and whether CTAP 2.1 keys give different outputs with and without the PIN|partly passed: on a key with a PIN, Windows asks for the PIN and reports UV=1 even with uv=discouraged (verified on YubiKey 5C NFC, Windows 11 26200, API 9), so the no-PIN mode was removed; alwaysUv and output differences with and without the PIN not run|
|7|Whether Windows forces PIN setup when a key without a PIN is used in PIN mode|passed: registering a discoverable credential on a key without a PIN makes Windows have the user set one (that registration's flags are UP only, UV=0) (verified on YubiKey 5C NFC, Windows 11 26200, API 9)|
|8|credProtect 3 (required) is accepted and really enforced (an assertion without the PIN fails), level 2 works, a key without credProtect fails cleanly|partly passed: a registration with credProtect 3 required and UV required succeeds and its extension output is credProtect=3 (verified on YubiKey 5C NFC, Windows 11 26200, API 9); a lookup without the PIN failing, level 2 and a key without credProtect not run|
|9|With 2 keys registered, the per-credential salts reach the right key, both keys plugged in at once works, and the answering key is identified|passed: with two keys in one allow list Windows reports the answering credential correctly, and the values differ per key (verified on YubiKey 5C NFC, Windows 11 26200, API 9)|
|10|One touch returns two salt values (`pbSecond`) equal to single-salt answers; otherwise two touches replace it|partly passed: one touch returns both 32-byte values (`pbSecond`) (verified on YubiKey 5C NFC, Windows 11 26200, API 9); equality with single-salt answers not run|
|11|The exact error when an already registered key is registered again|passed: registering an already registered key again with the exclude list fails as "already registered" (NTE_EXISTS) (verified on YubiKey 5C NFC, Windows 11 26200, API 9)|
|12|Error codes: user cancel, timeout, app cancel, PIN locked, cancel during PIN entry, a key without hmac-secret|not run|
|13|Three registration windows in a row (no re-plugging), the flow of windows, equal values|not run|
|14|Transport values for USB and NFC; phones and Windows Hello refused; BE and BS are 0 on a YubiKey 5; synced passkeys refused|partly passed: USB is 0x1 and NFC 0x2, BE and BS are always 0, the AAGUID is zero (no attestation); NFC works with the PIN typed first; a key plugged into USB when the window opens is used over USB (verified on YubiKey 5C NFC, Windows 11 26200, API 9); phones, Windows Hello and synced passkeys refused not run|
|15|The Windows window comes to the front, owner disabling breaks nothing, away and idle timers pause, and the 150 s cap works|partly passed: with owner window 0 MakeCredential fails at once with 0x80090027, with a real window it works (verified on YubiKey 5C NFC, Windows 11 26200, API 9); coming to the front, the timers and the 150 s cap not run|
|16|Thread and handle hygiene after many touches, no DLL loaded from beside the exe, `check_dll_planting.py --webauthn` passes|not run|
|17|The Windows window and error after a FIDO reset of a registered key; failure at the same step as a wrong password; removal with another key and re-adding|not run|
|18|Credential slot counts (about 25 / 100), the error when they are full, deleting one entry with `ykman fido credentials delete`, and whether Windows Settings can delete one|not run|
|19|Four real keys: remove one with one touch of another, each remaining key opens on its own, re-register the same key, re-lock all keys, an answer captured before stops working after re-locking|not run|
|19a|Several touches in one session (registering 4 keys in a row, pairing 3 keys), with key swaps and PIN entry|not run|
|19b|credProtect 3 stays enforced on every pairing and re-lock touch|not run|
|20|A real exFAT USB stick pulled, or the power cut, during the key-file replace, then automatic recovery|not run|
|21|Two real PCs and a 0.9 server: password change, taking it, equal codes; a key file shared on USB; joining an add-key race|not run|
|22|Two real PCs, two real keys, a `--key-sync` server: turning on, password change, addition (code), lost-key removal (pick) with review and history cleanup, simultaneous removals joined, a spare key paired later, turning off (deletion answered, no key file left on the server, a power cut midway), a new PC, and the vault lock on the real server's data folder|not run|
|23|Timing with real windows: re-locking 4 keys, pairing 3 keys, registering 2 keys, and taking another PC's code each finish within the default 1-minute auto-lock, and Win+L locks at once during any of them|not run|
