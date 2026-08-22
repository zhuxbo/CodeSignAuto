# SimplySignAuto

[中文（默认）](README.md) | [English](README.en.md)

## Installation requirements

- x64 Windows 10 22H2, a supported Windows 10 Enterprise/IoT Enterprise LTSC
  release, Windows 11, or Windows Server 2019/2022/2025 Standard or Datacenter
  with Desktop Experience. The system clock must be synchronized reliably.
- Stable major version 10 or later of both .NET Windows Desktop Runtime and
  ASP.NET Core Runtime. Setup never downloads a runtime and stops before product
  mutation when either runtime is missing. The target computer does not need the
  .NET SDK. Install both Windows x64 runtimes:
  - [.NET 10 / ASP.NET Core Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/10.0): select the latest stable Windows x64 installer under `ASP.NET Core Runtime`;
  - [WPF / .NET Desktop Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime): select the x64 installer under “Run desktop apps”.
  Desktop Runtime already includes the base .NET Runtime. SimplySignAuto does
  not use IIS and does not require the Hosting Bundle.
- Certum SimplySign Desktop for Windows 64-bit and
  `C:\Windows\System32\SimplySignPKCS.dll`. Download the Windows 64-bit
  `proCertum SmartSign + SimplySign Desktop` installer from the
  [official Certum page](https://support.certum.eu/en/software/procertum-smartsign/).
  Setup checks both the application and the PKCS#11 module before mutation.
- Windows SDK x64 `signtool.exe` is required for Authenticode. SignTool is not
  required when only PDF signing is used.
- Setup must run as an elevated administrator. Domain-member clients and member
  servers are supported; domain controllers are rejected.
- The SimplySign PKCS#11 module must load in the signing user's session and must
  expose the target certificate and private key.

The main product is a framework-dependent `win-x64` application. Python is not
required on the target. PDF/PAdES is an optional offline extension distributed
in a separate installer; without it, PDF controls remain hidden and the base
Authenticode capability is unaffected.

## Two fixed installation modes

You must select one mode during the first installation. All supported Windows
clients and Windows Server editions default to Manual signing; select Automatic
signing service when a server requires unattended signing. The mode is fixed
after installation and inherited by upgrades. To switch modes, uninstall and
reinstall the product.

- **Manual signing** is intended for a Windows 10/11 administrator who opens the
  app and submits local signing jobs on demand. It creates no Windows Service,
  dedicated user, AutoLogon, or HTTP API. The application must remain running
  until an active job finishes. The Jobs page retains history and protected
  signed results, which can be saved again to a selected location.
- **Automatic signing service** is intended for unattended Windows Server
  signing. Setup creates a LocalSystem Service, a fixed low-privilege
  `SimplySignAgent` user, protected AutoLogon, and a logon task. It exposes the
  HTTP API and lets an administrator use the WPF console in their own desktop
  session. Closing or exiting the console does not stop the Service, Agent, or
  signing jobs.

The Setup UI and application UI support Chinese and English. Setup initially
follows the Windows display language. With no saved preference, the application
defaults to Chinese and can be changed in Application Settings.

The service endpoint is HTTP only. When access crosses an untrusted network,
the deployer must provide an external HTTPS reverse proxy, certificate renewal,
hostname validation, and access control.

## Quick start

1. Download `SimplySignAutoSetup-<version>-win-x64.exe` and verify its
   Authenticode signature, timestamp, and expected publisher.
2. Run Setup, select a language and fixed installation mode, and complete the
   wizard.
3. In Manual mode, open SimplySignAuto directly. In Service mode, restart
   Windows when prompted and then open the public-desktop shortcut as
   Administrator.
4. Import the complete `otpauth://` activation content on the Activation page,
   then confirm the target certificate and signing capability are ready on the
   Overview page.
5. Service mode only: copy the one-time API token from
   `%ProgramData%\SimplySignAuto\install-token.txt` into the caller's secret
   store, verify access, and delete the file. See [HTTP API](docs/API.md).
6. Install `SimplySignAutoPdfSetup-<version>-win-x64.exe` only when PDF/PAdES is
   required.

## Verify release assets

Every public release contains the signed main installer. A PDF installer is
published at the same version only when the effective PDF helper, dependencies,
shared Setup, toolchain, or license inputs changed since the previous main
release. PDF version numbers may therefore have gaps. If a release has no new
PDF installer, keep using the latest installed compatible PDF extension.

Verify every installer present in the selected release:

```powershell
$setups = Get-ChildItem -LiteralPath . -File |
  Where-Object Name -Match '^SimplySignAuto(Pdf)?Setup-[0-9].*-win-x64\.exe$'
foreach ($setup in $setups) {
  $signature = Get-AuthenticodeSignature -LiteralPath $setup.FullName
  if ($signature.Status -ne 'Valid') { throw "release_signature_invalid: $setup" }
}
```

The main installer embeds a signed-catalog-closed payload with the application,
SQLite native dependency, runtime policy, offline notes, SPDX SBOM,
reproducibility report, MIT license, and complete third-party notices. The PDF
installer embeds a strict `extension.json`, signed helper, and the same license
documents. Each installer verifies its publisher, embedded media hashes, and
member closure before product mutation. Do not manually extract or modify the
embedded payload.

## First installation

Run the verified main installer:

```powershell
& '.\SimplySignAutoSetup-0.1.0-win-x64.exe'
```

Setup accepts no arguments and requests elevation through its application
manifest. It first checks Windows, runtimes, administrator state, non-domain-
controller state, SimplySign Desktop, and PKCS#11. The PDF helper is not a base
prerequisite.

Manual mode installs protected program media, a protected per-administrator
local job-data root, a public-desktop shortcut, an installation receipt, and the
uninstall registration. It creates no Service, user, AutoLogon, scheduled task,
or API token. `%ProgramData%\SimplySignAuto` contains only the administrator-
readable `install.json` receipt, not service configuration, a job database, or a
spool. Open the app after installation, import activation, and submit local jobs.

Service mode creates the `SimplySignAgent` user and profile, a random password
stored only in LSA private data, protected AutoLogon, the exact
AtLogOn/InteractiveToken Agent task, ProgramData, configuration, and the
LocalSystem Service. Copy the one-time API token to a secret store, delete the
temporary token file, and restart Windows so the nonzero signing-user session
and Agent can start. Administrators do not need to enter or operate that user's
desktop.

Both modes create the public-desktop SimplySignAuto shortcut. A missing SignTool
disables only Authenticode. A missing PDF extension does not block the base
product. Path, ACL, owner, or readback drift fails closed. Service mode also
rejects same-name user and existing AutoLogon conflicts. Setup rolls back only
exact-owned changes from the current attempt; uncertain rollback returns
`setup_state_uncertain`.

When Service mode detects external AutoLogon or saved credentials left after
AutoLogon was disabled, Setup offers **Disable safely and continue**, **Use
Manual signing**, and **Cancel**. After confirmation, safe disable only sets
`AutoAdminLogon` to `0`, removes the saved Windows AutoLogon credentials, and
verifies the result. It does not delete a user, change the account password, or
display, log, or use password contents. Setup then repeats the complete preflight and
continues. It refuses cleanup if SimplySignAuto ownership/uninstall state,
unexpected registry types, or any uncertain state is present; finish the
original uninstall or use Manual signing instead.

Service mode listens on `http://0.0.0.0:7080` by default and does not open the
firewall. Expose it only through a controlled LAN, VPN, or trusted reverse
proxy.

When PDF/PAdES is required, verify and run the latest compatible independent PDF
Setup. It validates the embedded helper length, SHA-256, Authenticode signature,
and publisher before atomic installation. The app shows PDF controls after its
next status refresh. Visible PDF appearances select a protected Windows system
font that covers the complete text; no suitable font returns
`pdf_appearance_font_missing`.

The same main Setup handles bounded in-place upgrades. It locks and inherits the
installed mode. Manual upgrades replace only the product media and uninstall
registration while preserving activation, settings, job history, and signed
results. Service upgrades drain jobs before media replacement and preserve the
API token, service configuration, job database, dedicated user, AutoLogon, and
activation. Both modes verify the receipt, owner, ACLs, registration, and
optional PDF extension before replacement. Mode migration, repair installation,
and downgrade are unsupported.

## Activation, UI, and local jobs

Import the complete `otpauth://` content on the WPF Activation page. Manual mode
parses it in the current administrator process and stores it with that user's
CurrentUser DPAPI. Service mode forwards it once through the mutually
authenticated local management channel to the signing-user Agent, which stores
it with that user's CurrentUser DPAPI. The Service does not persist or log the
URI. The input and clipboard are cleared after success, and no response returns
the secret.

Importing activation does not log in to SimplySign. Use Login on the Overview
page. Manual mode performs on-demand login for local jobs; Service mode can also
perform on-demand login before an accepted HTTP request is persisted. Login
rechecks the PKCS#11 token, certificate, and private key. Process presence alone
is not signing readiness.

Do not put activation content in command-line arguments, environment variables,
logs, tickets, or screenshots. The low-level `configure-otp` command writes only
the caller's CurrentUser DPAPI store and is reserved for explicit offline repair
inside the actual signing-user context.

The WPF application allows one instance per administrator SID. Closing the
window hides it to the tray. In Service mode, Exit closes only the control
console. In Manual mode, Exit stops the in-process worker and is refused while a
signing job is active.

On Quick Signing, select an administrator-readable
`.exe`/`.dll`/`.msi`/`.sys`/`.cat` or `.pdf`, then select a certificate and
parameters. The source remains read-only. A successful result is first retained
in the protected job directory and can then be saved to a selected destination;
overwrite requires explicit confirmation. The Jobs page retains history and
allows a still-retained successful result to be saved again. Both modes use a
persistent SQLite queue, one worker, recovery, and retention policies. Service-
mode local and HTTP jobs share the same queue.

## HTTP API and external HTTPS

The HTTP API exists only in Automatic signing service mode. The complete request
schema, responses, stable errors, idempotency rules, and retry behavior are in
[docs/API.md](docs/API.md).

The default endpoint is intended only for a controlled LAN, VPN, or same-host or
trusted reverse proxy. The product does not terminate TLS or manage server
certificates. Clients must validate certificates and hostnames normally when an
external reverse proxy provides HTTPS; do not use `curl -k`.

Anonymous liveness proves only that the Service and SQLite respond:

```bash
curl --fail-with-body "$BASE_URL/health/live"
```

Authenticated readiness requires the current Agent heartbeat and every
configured signing capability to be ready:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE_URL/v1/health/ready"
```

Except for liveness, every `/v1` route requires an exact
`Authorization: Bearer <token>` header. Never place the token in the repository.

## Retention, upgrade, and uninstall

Service-mode results default to 24 hours and are configurable from 0 to 168
hours in Service Settings. Manual-mode results default to 168 hours and use the
same range in Application Settings. `0` means permanent retention. The Jobs page
shows retained history and successful results. Active jobs are never expired.

API tokens exist only in Service mode and are rotated in Service Settings. A new
token is shown once and must be copied and acknowledged before the dialog can
close; the old token becomes invalid when the new configuration takes effect.

Before upgrade, close the WPF console and verify the new Setup signature. Manual
mode requires installed files to be replaceable and atomically rolls back media
and registration on failure. Service mode performs bounded drain, stops the
Agent task and Service, rechecks the offline queue, atomically replaces verified
media, and restarts and verifies the runtime. Failure restores the old media and
runtime when that can be proven. `restart_required`, `upgrade_drain_timeout`, or
`upgrade_state_uncertain` must be handled as reported; never overwrite Program
Files manually.

Uninstall from Windows Installed apps or run:

```powershell
& 'C:\Program Files\SimplySignAuto\SimplySignAuto.exe' uninstall
```

The PDF extension has its own uninstall entry. Removing it leaves the base
product intact. Removing the base product first verifies and removes an owned
PDF extension to avoid an orphan.

Manual uninstall removes the application, shortcut, receipt, registration, and
owned PDF extension. It also removes the DPAPI activation credential saved by
this product for the current administrator, while preserving job history and
signed results unless `uninstall --purge-data --confirm PURGE` is explicitly used.

Service uninstall verifies the exact install instance, owner marker, SID,
account, profile, AutoLogon/LSA fingerprint, task, Service, firewall, and ACLs
before mutation. It stops exact-owned runtime resources, logs off exact-SID
sessions, disables only product-owned AutoLogon, removes the created user and
profile, and quarantines ProgramData for restart cleanup. Follow the restart
instruction and do not move or delete Program Files until the cleanup task and
quarantine are gone.

Uninstall never removes or modifies Certum SimplySign Desktop,
`SimplySignPKCS.dll`, Certum certificates, or an operator-managed reverse proxy.

## Troubleshooting

- `installation_mode_change_requires_reinstall`: the installed mode is fixed;
  uninstall, rerun Setup, and select the other mode.
- `autologon_conflict` / `autologon_plaintext_password_present`: these affect
  only Service mode. Choose **Disable safely and continue** in Setup to turn off
  system AutoLogon and remove the saved Windows AutoLogon credentials, or use
  Manual signing. The action does not change the account password and does not
  display, log, or use saved password contents.
- `signtool_missing`: install or configure Windows SDK x64 SignTool. PDF-only
  operation is unaffected.
- `pdf_support_not_installed`: Authenticode remains available. Install the
  latest compatible PDF extension.
- `pdf_helper_missing` or `pdf_helper_tampered`: stop PDF signing and preserve
  the protected helper state for diagnosis; reinstall only from a verified
  release.
- `otp_*` or `clock_not_synchronized`: re-import activation from the WPF UI and
  synchronize the clock. Do not copy DPAPI files between users.
- Service `live` 503: check `SimplySignAuto.Service`, Event Log, the `jobs.db`
  volume, and ProgramData ACLs. Do not delete the database as a repair.
- Service `ready` 503 with `live` 200: verify the nonzero signing-user session,
  Agent task, clock, SimplySign Desktop, token, certificate, and private key.

## Build release installers

On a clean Windows x64 build machine, install .NET 10 SDK, Python 3.12, and `uv`:

```powershell
.\scripts\pre-release-check.ps1

$env:SIMPLYSIGN_SIGNING_BASE_URL = 'http://signing-ci.internal:7080'
$env:SIMPLYSIGN_SIGNING_BEARER_TOKEN = '<protected release secret>'
$env:SIMPLYSIGN_SIGNING_CERTIFICATE_SERIAL = '<certificate serial>'
.\scripts\build-release.ps1 -Version 0.1.0
```

The release check requires a complete, non-shallow, clean Git worktree. The
build produces and remotely signs the main Setup. It publishes the PDF Setup at
the same version only when the fail-closed Git decision proves an effective PDF
input changed since the unique nearest previous SemVer tag. A first release also
builds PDF Setup. Test, documentation, or release-helper changes outside the PDF
construction closure still run helper quality gates but skip PDF signing and
packaging.

The scripts do not commit, push, tag, or publish a remote Release. Signing
credentials are supplied at runtime and must never be recorded in the
repository, logs, or command line.

## License

SimplySignAuto is licensed under the [MIT License](LICENSE). Component copyright
notices and complete dependency license texts are in
[THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Every published installer
embeds both documents.
