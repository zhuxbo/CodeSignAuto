SimplySignAuto installation and release notes
==============================================

Read OPERATIONS.md before installation. This package targets Windows Server
2019, 2022 or 2025 Standard/Datacenter Desktop Experience, Windows 10 22H2,
supported Windows 10 Enterprise/IoT Enterprise LTSC releases, and supported
Windows 11 releases on x64. Domain members are supported, but domain
controllers are rejected. The framework-dependent application requires stable
.NET Windows Desktop Runtime and ASP.NET Core Runtime major version 10 or later.
Python is not required.

Setup offers two fixed modes. Manual signing is the client default and runs
local jobs in the current administrator's WPF process without a Service,
dedicated user, AutoLogon or HTTP API. Automatic signing service is the server
default and provides unattended signing through a LocalSystem Service and a
dedicated SimplySignAgent session. Upgrades inherit the installed mode. Switching
modes requires uninstall and reinstall.

Prerequisites
-------------

- Certum SimplySign Desktop must already be installed at
  C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe.
- C:\Windows\System32\SimplySignPKCS.dll must exist.
- Download the latest stable Windows x64 ASP.NET Core Runtime 10 from
  https://dotnet.microsoft.com/en-us/download/dotnet/10.0 and .NET Desktop
  Runtime 10 from https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime.
  Desktop Runtime includes the base .NET Runtime. The product does not require
  the SDK or IIS Hosting Bundle on the target.
- Download proCertum SmartSign + SimplySign Desktop for Windows 64-bit from
  https://support.certum.eu/en/software/procertum-smartsign/.
- Windows SDK x64 SignTool enables Authenticode. If it is absent, setup reports
  authenticode_disabled_signtool_missing for that optional capability.
- Run setup and the WPF console as an elevated local administrator.

Package contents
----------------

- The public release always contains the signed, versioned main installer,
  SimplySignAutoSetup-<version>-win-x64.exe. It also contains
  SimplySignAutoPdfSetup-<version>-win-x64.exe only when effective PDF helper,
  dependency, shared Setup, toolchain or license inputs changed since the
  previous main release. Every published installer embeds its payload and
  accepts no arguments. PDF versions therefore may have gaps, but when a PDF
  installer is published its version matches that main release.
- SimplySignAuto.exe and e_sqlite3.dll: framework-dependent Service, headless
  Agent and administrator WPF app payload.
- install-prerequisites.ps1 and runtime-prerequisites.json: signed prerequisite
  checker and strict runtime policy. Missing supported .NET runtimes stop setup
  before product mutation; the installer never downloads or installs runtimes.
- release-files.cat: signed catalog closing the complete embedded payload.
- agent.example.json and service.example.json: advanced schema references only;
  standard setup generates protected configuration automatically.
- OPERATIONS.md: API, health, retention, upgrade and incident guide.
- sbom.spdx.json and reproducibility.json: dependency inventory and repeat-
  build comparison.
- LICENSE.txt: SimplySignAuto MIT license.
- THIRD-PARTY-NOTICES.txt: dependency attributions and complete license texts.

The main installer contains only the base product and enables Authenticode.
The PDF installer contains extension.json, the signed SimplySignPdfSigner
executable, and the two license documents. The helper is never downloaded by the product.
Visible PDF stamps select a font that covers the required text from the protected
Windows Fonts directory; no font file is bundled in the helper.
Both embedded archives are internal build inputs, not user-facing ZIP files.

Standard install
----------------

1. Verify the Authenticode signature, timestamp and expected publisher of every
   installer EXE present in the selected release.
2. Run the main Setup EXE. It accepts no arguments and requests elevation
   through its application manifest. Select Chinese or English and one fixed
   installation mode. Setup verifies its own publisher and embedded signed
   media, then atomically stages the validated payload into
   C:\Program Files\SimplySignAuto.
3. Before the first mutation, Setup verifies Windows/admin/non-domain-controller
   state, SimplySign Desktop and PKCS#11. Missing SimplySign prerequisites stop
   setup without creating a user.
4. Manual mode creates protected per-administrator local job data, the public
   shortcut, receipt and registration. It creates no Service, user, AutoLogon,
   task or API token. ProgramData contains only install.json, not service
   configuration, a job database or spool. Open SimplySignAuto directly, import
   activation and submit local jobs. History and signed results are retained.
5. Service mode creates the low-privilege SimplySignAgent account and profile,
   a non-displayed random password held only in Windows LSA private data,
   protected AutoLogon, the exact AtLogOn/InteractiveToken Agent task,
   ProgramData, generated configuration and the LocalSystem Service. It refuses
   an existing same-name user, another AutoLogon, owner/SID/ACL conflicts or
   failed readback. Failure rolls back only exact-owned changes; uncertain
   rollback reports setup_state_uncertain.
6. Service mode only: copy the one-time API token to client secret storage and
   delete C:\ProgramData\SimplySignAuto\install-token.txt after verification.
   Restart Windows when requested so the signing user's nonzero session starts
   the headless Agent. Administrators never operate that user's desktop.
7. Run SimplySignAuto.exe as Administrator. Manual mode hosts the signing worker
   in this process and refuses Exit while a job is active. Service mode opens an
   elevated control console without loading agent.json or starting another
   Agent.
8. Only when PDF/PAdES is required, install the latest compatible PDF Setup EXE.
   A main release without PDF changes does not publish a new PDF installer, so
   PDF version numbers may skip main versions. When published, the PDF version
   matches that main release; schemaVersion defines manifest compatibility and
   productVersion records extension build provenance. Setup verifies and
   atomically installs the embedded signed helper without network access. Until
   then, PDF controls remain hidden and base readiness depends only on
   Authenticode.

An exact existing SimplySignAuto installation selects a bounded in-place upgrade
and locks the installed mode. Manual upgrades replace only verified media and
registration while preserving per-administrator activation, settings, history
and signed results. Service upgrades verify the owned identity, ACLs, service,
task, AutoLogon, registration, installed media and optional PDF extension before
draining jobs. New media is verified in protected staging, switched atomically
on the same volume, and rolled back if the new runtime cannot be verified.
Unknown or drifted resources stop before replacement; mode migration, repair
installs and downgrades are unsupported.

Service mode's default endpoint is HTTP port 7080 and is intended only for a
controlled internal network, VPN or trusted reverse proxy. Setup does not open
the firewall. Manual mode exposes no endpoint. The product does not terminate
TLS or manage server certificates. To expose an HTTPS endpoint, configure a
reverse proxy outside the product and forward it to the HTTP port. The operator
owns certificate renewal, hostname validation and proxy access control.

Activation and control
----------------------

Use the Administrator WPF Activation page to import the otpauth URI. Manual mode
parses and protects it with the current administrator's CurrentUser DPAPI.
Service mode authenticates the LocalSystem Service, which transiently forwards
the request to the signing-user Agent; that Agent parses and protects it with
its own CurrentUser DPAPI. The Service does not persist the URI and responses
never return the secret. The configure-otp repair command writes only the
caller's CurrentUser store and must run as the actual signing user.

Refresh, login, clear and certificate discovery are serialized against signing.
In Manual mode they execute in the current process; Exit is refused while a job
is active. In Service mode they execute in the Agent, and closing or exiting the
administrator console does not stop the Service, Agent, SimplySign Desktop or
queued/current jobs.

For quick signing, the administrator console opens the selected private file.
Manual mode copies it into the current administrator's protected spool and signs
with the in-process worker. Service mode uploads through a Service-issued spool
lease; the Agent receives no administrator Desktop path. A successful result is
retained with job history and can be saved again while still in its retention
period.

Service-mode quick checks
------------

Anonymous liveness proves only that the Service and SQLite respond:

   curl.exe http://signing-ci.internal:7080/health/live

Authenticated readiness requires the current Agent heartbeat and every
configured capability to be ready:

   curl.exe -H "Authorization: Bearer TOKEN" http://signing-ci.internal:7080/v1/health/ready

Do not use curl -k. Process presence alone is not readiness.

Uninstall
---------

Use Windows Settings > Apps > Installed apps > SimplySignAuto, or run from
PowerShell and wait for the GUI-subsystem process:

   $process = Start-Process -FilePath 'C:\Program Files\SimplySignAuto\SimplySignAuto.exe' `
     -ArgumentList 'uninstall' -NoNewWindow -Wait -PassThru
   $process.ExitCode

Once elevated, the main-product uninstall writes a bounded structured log to
%LocalAppData%\SimplySignAuto\logs\uninstall.log. It contains only the product
version, Windows build, persisted-state classification and stable error code;
it never contains tokens, SIDs, paths or configuration contents. Missing,
invalid or conflicting install metadata stops uninstall before mutation. A
restart cannot repair that persistent-state failure, so keep the installation
directory and this log for diagnosis.

PDF Support has its own Installed apps uninstall entry. Removing it leaves the
base product intact. Removing the base product also removes an installed PDF
extension after the same exact-ownership checks.

Manual uninstall removes the application, shortcut, receipt, registration and
owned PDF extension. It preserves per-administrator history and signed results
unless uninstall --purge-data --confirm PURGE is explicitly used. Restart
Windows after success to finish physical cleanup of the program files.

Service uninstall requests elevation when needed. Before any mutation it
verifies the exact install instance, owner
marker, SID, account, profile receipt/ProfileList, AutoLogon/LSA secret,
task/service/firewall and controlled directory ACLs. Any replacement or
uncertain readback rejects the entire operation before mutation.

For the standard product-managed account, uninstall stops the Agent task and
Service, logs off exact-SID sessions, disables only product-owned AutoLogon,
deletes the exact-owned user and profile, then quarantines ProgramData. The
protected disabled-AutoLogon receipt makes an interrupted uninstall retryable.
SYSTEM completes physical quarantine and exact owner/SID Winlogon/LSA cleanup
cleanup after restart. Keep C:\Program Files\SimplySignAuto unchanged until
that restart completes and the SimplySignAuto.Purge.* task/quarantine are gone;
the cleanup task requires the same executable path and hash. Advanced
ExistingUser installations preserve the external account and profile.

Uninstall never removes or modifies Certum SimplySign Desktop,
SimplySignPKCS.dll, Certum installation records, Certum certificates or
the operator's reverse proxy.

Secret incident
---------------

If a Bearer token leaks, rotate it from Service Settings in the elevated
administrator console. If otpauth/TOTP leaks, revoke or reset it with Certum and use the
administrator console to clear and re-import. Never paste a secret into logs,
tickets, process arguments, environment variables or screenshots.
