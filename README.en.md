# SimplySignAuto

[中文（默认）](README.md) | [English](README.en.md)

SimplySignAuto provides Authenticode signing, optional PDF/PAdES signing, local
WPF manual signing, and unattended Windows Server signing through an HTTP API.

## Installation requirements

### Supported systems

The target must be x64 and have a reliably synchronized system clock.

- Windows 10 22H2;
- supported Windows 10 Enterprise / IoT Enterprise LTSC editions;
- Windows 11;
- Windows Server 2019, 2022, or 2025 Standard/Datacenter Desktop Experience.

### Required components and downloads

| Component | Download | Select |
| --- | --- | --- |
| ASP.NET Core Runtime 10 | [.NET 10 downloads](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) | The latest stable Windows x64 installer under `ASP.NET Core Runtime` |
| WPF / .NET Desktop Runtime 10 | [.NET Desktop Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime) | The x64 installer under “Run desktop apps” |
| Certum SimplySign Desktop | [Certum downloads](https://support.certum.eu/en/cert-offer-software-and-libraries/) | Windows 64-bit `SimplySign Desktop`; proCertum SmartSign is not required |
| Windows SDK Signing Tools | [Windows SDK downloads](https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads) | Authenticode only: use the latest stable Installer and select only `Windows SDK Signing Tools for Desktop Apps` |

Before installation, confirm that:

- .NET Windows Desktop Runtime and ASP.NET Core Runtime are version 10 or a later major version;
- `C:\Windows\System32\SimplySignPKCS.dll` exists;
- the signing user can load the SimplySign PKCS#11 module and enumerate the target certificate and private key;
- Windows SDK Signing Tools are installed, including x64 `signtool.exe`, when Authenticode is required.

Notes:

- Setup does not download or install .NET. Missing runtimes or SimplySign Desktop are reported before system mutation.
- The target does not need the .NET SDK, Python, IIS, or the Hosting Bundle.
- A full Windows SDK development workload or Visual Studio is not required; Authenticode only needs Windows SDK Signing Tools.
- Desktop Runtime already includes the base .NET Runtime.
- PDF-only operation does not require SignTool.

### Main application and PDF extension

- The main application is a `win-x64` framework-dependent single file with full Authenticode support.
- The PDF helper exists only in the independent PDF extension Setup and is never downloaded by the main application.
- PDF controls remain hidden until the extension is installed.
- The product listens on HTTP only and does not manage TLS certificates. Use an external reverse proxy for HTTPS.

## Choose an installation mode

The first installation requires one fixed mode. Manual signing is selected by default.

| Item | Manual signing | Automatic signing service |
| --- | --- | --- |
| Intended use | Windows 10/11 or administrator-operated signing | Unattended Windows Server signing |
| Signing runtime | Runs while the current administrator app is open | Background Service and dedicated signing user |
| Windows Service | Not created | LocalSystem Service |
| Dedicated user / AutoLogon | Not created | `SimplySignAgent` with protected AutoLogon |
| HTTP API | Not exposed | Exposed |
| Closing the console | Allowed after the active job completes | Does not stop background jobs |

Mode rules:

- Upgrades inherit the installed mode.
- Switching modes requires uninstall and reinstall.
- Rerunning Setup cannot migrate or repair the mode.

Setup and the application support Chinese and English. Setup initially follows the
Windows display language. The application defaults to Chinese when no preference
has been saved and can be changed under Application Settings.

## Quick start

1. Download `SimplySignAutoSetup-<version>-win-x64.exe`.
2. Verify its Authenticode signature and timestamp.
3. Run Setup and select the language and installation mode.
4. In Manual mode, open SimplySignAuto after installation.
5. In Service mode, restart when prompted, then open the public-desktop shortcut as Administrator.
6. Import the complete `otpauth://` activation content on the Activation page.
7. Confirm that the target certificate and required signing capability are ready on Overview.
8. If PDF is required, install the PDF Setup included in the current Release; otherwise keep the latest compatible extension.

Service mode also creates a one-time API token:

1. Read `%ProgramData%\SimplySignAuto\install-token.txt`.
2. Store the token in the caller's secret store immediately.
3. Delete the file after API access is verified.
4. The Service retains only the token SHA-256.

See the complete [HTTP API documentation](docs/API.md).

## Verify release assets

Every public Release contains:

- `SimplySignAutoSetup-<version>-win-x64.exe`.

When an effective PDF input changed since the previous main release, it also contains:

- `SimplySignAutoPdfSetup-<version>-win-x64.exe`.

PDF versions may therefore have gaps, for example from `0.1.0` directly to `0.1.3`.

Verify installers in the current directory with PowerShell:

```powershell
$setups = Get-ChildItem -LiteralPath . -File |
  Where-Object Name -Match '^SimplySignAuto(Pdf)?Setup-[0-9].*-win-x64\.exe$'

foreach ($setup in $setups) {
  $signature = Get-AuthenticodeSignature -LiteralPath $setup.FullName
  if ($signature.Status -ne 'Valid') {
    throw "release_signature_invalid: $setup"
  }
  if ($null -eq $signature.TimeStamperCertificate) {
    throw "release_timestamp_missing: $setup"
  }
}
```

Package boundaries:

- The main Setup embeds the application, SQLite native dependency, configuration example, runtime policy, offline notes, SPDX SBOM, reproducibility report, MIT license, and third-party notices.
- The PDF Setup embeds a strict `extension.json`, the signed helper, MIT license, and third-party notices.
- Setup validates its publisher, embedded media hashes, and member closure before installation.
- Users should not manually unpack the embedded media.

## Installation and upgrade

### First installation

After signature verification, run the main Setup:

```powershell
& '.\SimplySignAutoSetup-0.1.0-win-x64.exe'
```

Setup accepts no arguments and requests UAC through its application manifest. Its
preflight checks cover:

- Windows version and architecture;
- .NET runtimes;
- administrator rights and a non-domain-controller host;
- SimplySign Desktop and PKCS#11;
- existing installation, directory, user, and AutoLogon conflicts.

The PDF helper is not a base-installation prerequisite.

#### Manual signing mode

Installed resources:

- protected program media;
- a local job-data directory for the current administrator;
- a public-desktop shortcut;
- an installation receipt and uninstall registration.

This mode creates no Service, dedicated user, AutoLogon, scheduled task, or API
token. `%ProgramData%\SimplySignAuto` contains only the administrator-readable
`install.json` receipt.

#### Automatic signing service mode

Installed resources:

- a LocalSystem Service;
- the low-privilege `SimplySignAgent` user;
- a Windows profile;
- a random password stored only in LSA private data;
- protected AutoLogon;
- an AtLogOn/InteractiveToken Agent task;
- ProgramData, configuration, and a one-time API token.

Restart when prompted. The administrator does not need to enter or operate the
signing user's desktop.

The Service listens on `http://0.0.0.0:7080` by default. Setup does not open the
firewall. Use it only on a controlled LAN, VPN, or behind a trusted reverse proxy.

#### Existing AutoLogon conflicts

When Service mode detects external AutoLogon or saved residual credentials, Setup offers:

- Disable safely and continue;
- Use Manual signing instead;
- Cancel.

Disable safely and continue only:

- sets `AutoAdminLogon` to `0`;
- removes saved Windows AutoLogon credentials;
- verifies the result by reading it back;
- repeats the full preflight.

It does not delete a user, change an account password, or display, log, or use
password contents. Setup refuses cleanup when ownership, uninstall state, registry
types, or any other relevant state cannot be proven.

### PDF extension

When PDF/PAdES is required, run the independent Setup:

```powershell
& '.\SimplySignAutoPdfSetup-<version>-win-x64.exe'
```

Rules:

- If the current Release has no PDF Setup, keep the latest compatible extension.
- PDF versions do not need to be consecutive or equal to the main version.
- The main application uses `schemaVersion` for compatibility; `productVersion` records the extension build source.
- Setup verifies helper length, SHA-256, Authenticode, and publisher offline.
- PDF controls appear after the next management-state refresh.
- If no protected Windows system font covers all visible text, signing returns `pdf_appearance_font_missing`.

### In-place upgrade

The same main Setup handles clean installation and bounded in-place upgrade.

Common rules:

- lock and inherit the installed mode;
- verify receipt, owner, ACLs, product registration, and PDF extension;
- fail closed before replacement on unknown files, path drift, or identity mismatch;
- do not support mode migration, repair installation, or downgrade.

Manual upgrades preserve:

- current-administrator settings and DPAPI activation;
- job history, spool, and signed results;
- a compatible PDF extension.

Service upgrades drain jobs before replacement and preserve:

- API token and Service configuration;
- job database and spool;
- dedicated user, AutoLogon, and DPAPI activation;
- a compatible PDF extension.

Do not manually overwrite Program Files after any of these errors:

- `restart_required`;
- `upgrade_drain_timeout`;
- `upgrade_state_uncertain`.

## Activation, login, and local signing

### Import activation

Administrator imports the complete `otpauth://` content on the WPF Activation page.

- Manual mode parses and stores it with the current administrator's CurrentUser DPAPI.
- Service mode forwards it over the mutually authenticated local management channel for storage by the dedicated signing-user Agent.
- The Service does not persist or log the activation URI.
- On success, the input and clipboard are cleared and no protocol response returns the secret.

Importing is not logging in. Select Login on the Overview page afterward.

### Login and readiness

- Idle sessions do not perform background login or retry.
- Manual mode logs in on demand for a local job.
- Service mode can log in after HTTP preflight and before creating a job.
- Login rechecks the PKCS#11 token, certificate, and private key.
- Failed login leaves no new job or uploaded file.
- A SimplySign Desktop process alone is not signing readiness.

To replace activation:

1. Confirm there is no active job.
2. Select Clear on the Activation page and confirm.
3. Wait for the current session to close and the certificate list to clear.
4. Import the new complete activation content.

This does not remove a Certum account or signing certificate.

The low-level `configure-otp` command is only for explicit offline repair in the
actual signing-user context:

```powershell
Get-Clipboard | .\SimplySignAuto.exe configure-otp
Set-Clipboard -Value ''
```

Never put the activation URI in command-line arguments, environment variables,
logs, tickets, or screenshots.

### WPF, tray, and job history

- One WPF instance is allowed per administrator SID; another launch activates it.
- Closing the window hides it to the tray.
- Exiting the Service-mode console does not stop the Service, Agent, or background jobs.
- Manual mode refuses Exit while a job is active.
- The Jobs page keeps history and successful results that remain inside retention.

### Local quick signing

Supported inputs:

- `.exe`, `.dll`, `.msi`, `.sys`, and `.cat`;
- `.pdf` when the PDF extension is installed.

Signing flow:

1. Select an administrator-readable source file, certificate, and parameters.
2. The application copies the input into the protected spool for the current mode.
3. One worker signs and verifies the file.
4. A successful result is retained in the protected job directory.
5. The console verifies size/hash before saving to the selected destination.

The source remains read-only and overwriting requires explicit confirmation. In
Service mode, local and HTTP jobs share the same persistent SQLite queue.

## HTTP API and external HTTPS

The HTTP API exists only in Automatic signing service mode. See
[docs/API.md](docs/API.md) for the complete schemas, errors, idempotency, and retry rules.

Deployment boundaries:

- default address: `http://<server>:7080`;
- direct use only on a controlled LAN, VPN, or behind a trusted reverse proxy;
- the product does not terminate TLS or manage server certificates;
- HTTPS clients must validate certificates and hostnames normally; do not use `curl -k`;
- every `/v1` route except `GET /health/live` requires a Bearer token.

Health checks:

```bash
curl --fail-with-body "$BASE_URL/health/live"
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/v1/health/ready"
```

- `live` proves only that the Service and SQLite respond.
- `ready` checks the Agent session, heartbeat, SimplySign, token, certificate, and private key.
- Process presence or `live` 200 is not signing readiness.

Asynchronous submission:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: build-20260809-app-x64' \
  -F 'file=@./app.exe;type=application/octet-stream' \
  -F 'parameters={"kind":"authenticode","certificateSerialNumber":"52A1B4C9","digestAlgorithm":"sha256","appendSignature":false}' \
  "$BASE_URL/v1/jobs"
```

Requests accept multipart uploads only, not server-local paths or remote URLs. The
single-file limit is 512 MiB.

## Retention, settings, and uninstall

### Result retention

| Mode | Default | Configurable range |
| --- | --- | --- |
| Manual signing | 168 hours | 0–168 hours |
| Automatic signing service | 24 hours | 0–168 hours |

`0` means permanent retention. Active jobs are never expired.

### API token rotation

API tokens exist only in Service mode and can be rotated under Service Settings.

- A new token is shown once.
- It must be copied and acknowledged before the dialog can close.
- The old token becomes invalid when the new configuration takes effect.

### Uninstall

Prefer Windows **Settings → Apps → Installed apps**, or run:

Windows Settings shows localized uninstall progress, results, and restart guidance without opening
a command window. From PowerShell, use a wait-style invocation to keep stable output and error codes
in the current terminal for administration and troubleshooting:

```powershell
$process = Start-Process -FilePath 'C:\Program Files\SimplySignAuto\SimplySignAuto.exe' `
  -ArgumentList 'uninstall' -NoNewWindow -Wait -PassThru
$process.ExitCode
```

The PDF extension has a separate uninstall entry. Removing it does not affect the
main application. Removing the main application first verifies and removes an
installed PDF extension.

Manual uninstall:

- removes the application, shortcut, receipt, and uninstall registration;
- removes the DPAPI activation saved by this product for the current administrator;
- preserves job history and signed results by default;
- requires a Windows restart to finish physical cleanup of the program files.

Only this explicit command removes the controlled data directory:

```powershell
$process = Start-Process -FilePath 'C:\Program Files\SimplySignAuto\SimplySignAuto.exe' `
  -ArgumentList 'uninstall', '--purge-data', '--confirm', 'PURGE' `
  -NoNewWindow -Wait -PassThru
$process.ExitCode
```

Service uninstall:

- verifies the install instance, owner, SID, account, profile, AutoLogon, task, Service, firewall, and ACLs before mutation;
- removes only exact-owned Service, task, user, profile, AutoLogon, and controlled data;
- requires the prompted restart and completion of the purge task and quarantine cleanup;
- requires the Program Files package directory to remain in place until restart cleanup finishes.

Uninstall never modifies Certum SimplySign Desktop, `SimplySignPKCS.dll`, Certum
certificates, or an operator-managed reverse proxy.

## Troubleshooting

| Symptom or code | Action |
| --- | --- |
| `live` 503 | Check `SimplySignAuto.Service`, Event Log, the `jobs.db` volume, and ProgramData ACLs. Do not delete the database. |
| `ready` 503 with `live` 200 | Check the nonzero signing-user session, Agent task, clock, SimplySign Desktop, token, certificate, and private key. |
| `installation_mode_change_requires_reinstall` | Uninstall, rerun Setup, and select the other mode. |
| `autologon_conflict` / `autologon_plaintext_password_present` | Select **Disable safely and continue** in Service-mode Setup, or use Manual mode. |
| `signtool_missing` | Install or configure Windows SDK x64 SignTool. PDF-only use is unaffected. |
| `pdf_support_not_installed` | Install the latest compatible PDF extension. Authenticode remains available. |
| `pdf_helper_missing` / `pdf_helper_tampered` | Stop PDF signing, preserve evidence, and reinstall from a verified Release. |
| `otp_*` / `clock_not_synchronized` | Re-import activation in the console and synchronize the clock. Do not copy DPAPI files between users. |
| Long-running `waiting_for_agent` | Restore readiness before creating more jobs with new idempotency keys. |
| `result_corrupt` | Preserve the correlation ID, check storage and ACLs, and create a new job from the source. |

## Secret exposure response

If an API token, activation content, reverse-proxy key, or signing credential may be exposed:

1. Isolate the caller and retain only non-secret time, host, correlation ID, and audit evidence.
2. API token: rotate it under Service Settings and revoke old client copies.
3. Activation: revoke or reset it through Certum, clear the old state in the console, and re-import.
4. TLS private key: revoke and replace it through the reverse proxy or certificate system.
5. If executables, the helper, PKCS#11, or ACLs may be altered, stop signing and restore from a verified release.

Do not paste the secret into logs, tickets, command lines, or screenshots.

## Build release installers

Build-machine requirements:

- a clean, complete, non-shallow Git worktree;
- Windows x64;
- .NET 10 SDK;
- Python 3.12;
- `uv`.

Basic flow:

```powershell
.\scripts\pre-release-check.ps1

$env:SIMPLYSIGN_SIGNING_BASE_URL = 'http://signing-ci.internal:7080'
$env:SIMPLYSIGN_SIGNING_BEARER_TOKEN = '<protected release secret>'
$env:SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL = '<certificate serial>'
.\scripts\build-release.ps1 -Version 0.1.0
```

The release script runs:

- Python tests, ruff, and frozen-dependency verification;
- NuGet locked restore and .NET tests;
- two matching framework-dependent publishes;
- SPDX SBOM, catalog, closure, and signature verification;
- remote signing of the main Setup;
- same-version PDF build and signing when effective PDF inputs changed.

Public output is exactly one main Setup plus one PDF Setup when required for this
release. The scripts do not commit, push, tag, or create a GitHub Release.

Credential-free local wrapper:

```powershell
.\scripts\build-local-signed-release.ps1 `
  -Version <version> `
  -SigningBaseUrl 'http://signing-host.internal:7080' `
  -BearerTokenPath 'C:\BuildSecrets\simplysign-token.txt' `
  -SigningReferencePath 'C:\BuildSecrets\SimplySignAuto-reference.exe' `
  -DotnetRoot 'C:\Program Files\dotnet' `
  -UvPath '<path-to-uv.exe>'
```

The Bearer token must enter release subprocesses only through a protected file or
process environment. Never record it in the repository, command line, or logs.

## License

SimplySignAuto uses the [MIT License](LICENSE). Complete third-party copyright and
license texts are in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Both files
are embedded in every released installer.
