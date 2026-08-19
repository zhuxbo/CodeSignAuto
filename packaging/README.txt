SimplySignAuto installation and release notes
==============================================

Read OPERATIONS.md before installation. This package targets Windows Server
2019, 2022 or 2025 Standard/Datacenter Desktop Experience, supported Windows
10 Enterprise/IoT Enterprise LTSC releases, and supported Windows 11 releases
on x64. Domain members are supported, but domain controllers are rejected. The
framework-dependent application requires stable .NET Windows Desktop Runtime
and ASP.NET Core Runtime major version 10 or later. Python is not required.

Prerequisites
-------------

- Certum SimplySign Desktop must already be installed at
  C:\Program Files\Certum\SimplySign Desktop\SimplySignDesktop.exe.
- C:\Windows\System32\SimplySignPKCS.dll must exist.
- Windows SDK x64 SignTool enables Authenticode. If it is absent, setup reports
  authenticode_disabled_signtool_missing for that optional capability.
- Run setup and the WPF console as an elevated local administrator.

Package contents
----------------

- The public release contains exactly two signed, versioned installers:
  SimplySignAutoSetup-<version>-win-x64.exe and
  SimplySignAutoPdfSetup-<version>-win-x64.exe. Both embed their payload and
  accept no arguments.
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

1. Verify the Authenticode signature, timestamp and expected publisher of both
   versioned installer EXEs.
2. Run the main Setup EXE. It accepts no arguments and requests elevation
   through its application manifest. Setup verifies its own publisher and the
   embedded signed media, then atomically stages the validated payload into
   C:\Program Files\SimplySignAuto.
3. Before the first mutation, Setup verifies Windows/admin/non-domain-controller
   state, SimplySign Desktop and PKCS#11. Missing SimplySign prerequisites stop
   setup without creating a user.
4. Setup creates the low-privilege SimplySignAgent account and profile, a
   non-displayed random password held only in Windows LSA private data,
   protected AutoLogon, the exact AtLogOn/InteractiveToken Agent task,
   ProgramData, generated configuration and the LocalSystem Service. It refuses
   an existing same-name user, another AutoLogon, owner/SID/ACL conflicts or
   failed readback. Failure rolls back only exact-owned changes; uncertain
   rollback reports setup_state_uncertain.
5. Copy the one-time API token to client secret storage and delete
   C:\ProgramData\SimplySignAuto\install-token.txt after verification.
6. When setup prints restart_required, restart Windows. Windows establishes the
   signing user's nonzero interactive session and starts the headless Agent.
   Administrators never need to log into or operate that user's desktop.
7. Log in only as Administrator and run SimplySignAuto.exe in that administrator
   desktop. It opens the elevated control console; it does not load agent.json
   or start another Agent.
8. Only when PDF/PAdES is required, run an independently versioned PDF Setup
   EXE. The extension version does not need to match the main product version;
   schemaVersion defines manifest compatibility and productVersion records
   extension build provenance. Setup verifies and atomically installs the
   embedded signed helper without network access. Until then, PDF controls
   remain hidden and base readiness depends only on Authenticode.

An exact existing SimplySignAuto installation selects the bounded in-place
upgrade path. Setup verifies the owned identity, ACLs, service, task, AutoLogon,
registration, installed media and optional PDF extension before draining jobs.
New media is verified in protected staging, switched atomically on the same
volume, and rolled back if the new service or agent cannot be verified. User
data, API token, activation and compatible PDF support are preserved. Missing
signing-user sessions, occupied installed files and older builds without the
drain contract return restart_required. Unknown or drifted resources still stop
before replacement; repair installs and downgrades are unsupported.

The default endpoint is HTTP port 7080 and is intended only for a controlled
internal network, VPN or trusted reverse proxy. Setup does not open the firewall.
The product does not terminate TLS or manage server certificates. To expose an
HTTPS endpoint, configure a reverse proxy outside the product and forward it to
the HTTP port. The operator owns certificate renewal, hostname validation and
proxy access control.

Activation and control
----------------------

Use the Administrator WPF Activation page to import the otpauth URI. The
console authenticates the LocalSystem Service, which transiently forwards the
request to the signing-user Agent. The Agent parses it again and writes only its
own CurrentUser DPAPI store. The Service does not persist the URI and responses
never return the secret. Do not run configure-otp as Administrator: that legacy
command writes the caller's CurrentUser store.

Refresh, login, clear and certificate discovery also execute in the Agent. They
are serialized against signing. Closing or exiting the administrator console
does not stop the Service, Agent, SimplySign Desktop or queued/current jobs.

For quick signing, the administrator console opens the selected private file,
uploads it through a Service-issued spool lease and verifies size/hash again
before saving the result. The Agent receives no administrator Desktop path.
Create, complete and result operations preserve the established timeouts and
complete retries the same request/job/lease after a transport interruption.

Quick checks
------------

Anonymous liveness proves only that the Service and SQLite respond:

   curl.exe http://signing-ci.internal:7080/health/live

Authenticated readiness requires the current Agent heartbeat and every
configured capability to be ready:

   curl.exe -H "Authorization: Bearer TOKEN" http://signing-ci.internal:7080/v1/health/ready

Do not use curl -k. Process presence alone is not readiness.

Uninstall
---------

Use Windows Settings > Apps > Installed apps > SimplySignAuto, or run:

   "C:\Program Files\SimplySignAuto\SimplySignAuto.exe" uninstall

PDF Support has its own Installed apps uninstall entry. Removing it leaves the
base product intact. Removing the base product also removes an installed PDF
extension after the same exact-ownership checks.

The installed executable requests elevation when needed. Before any mutation,
production uninstall verifies the exact install instance, owner
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
