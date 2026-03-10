# utils/bin/

This directory is used to store portable tool binaries (e.g., `openssl.exe`) required by the toolkit.

## How to set up

Run the following command from the project root:

```powershell
.\Install-Dependencies.ps1
```

This will automatically download and extract the required tools into this directory.

## Search order for OpenSSL

The toolkit resolves the OpenSSL executable in the following priority:

1. Explicit `-OpenSsl` parameter passed to a script
2. `utils/bin/openssl.exe` (project-local portable binary)
3. `Tools.OpenSsl` path configured in `config.json`
4. `C:\Program Files\Git\usr\bin\openssl.exe` (Git for Windows)
5. `openssl` found in system `PATH`

## Note

Binary files in this directory are excluded from Git via `.gitignore`.
Only this README is tracked.
