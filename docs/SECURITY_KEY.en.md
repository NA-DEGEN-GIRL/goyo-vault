# Security keys (experimental)

[한국어](SECURITY_KEY.md) · <b>English</b>

> [!WARNING]
> **Experimental: not verified with real security keys. Not in the default build or the release ZIP.**

Goyo Vault 0.9.0 is getting an optional feature that locks the key file with both the password and a security key (a FIDO2 key such as a YubiKey). It is only in a Goyo Vault you build yourself with the security-key feature. How to turn it on, register several keys, and what to do when a key is lost will be written here once the feature is complete.

**What the default build does with a security-key file.** The `goyo-vault.exe` of the release ZIP does not open a key file locked by a security key (one whose first 8 bytes start with `GOYOKH` or `GOYOKS`). As soon as you choose such a file, and when you press 'Open' or 'Restore', it looks at the first 8 bytes only, before checking any password, and says "This key file opens only with a security key (YubiKey or similar)…". It never says the password is wrong, does not count a failed attempt and starts no retry delay. If the file is cut short, or a newer version made it so that it fails the format check, it adds "The file may also be damaged, or made by a newer version." The default build cannot tell whether such a file is damaged, so it never replaces it with a temp file (`.goyotmp`) left by an interrupted save either. A vault file saved under a security-key file, opened with a key file that lacks its key, gets "This vault file was saved with a key file locked by a security key…" and is not opened. Opening any of these files needs a build with the security-key feature.
