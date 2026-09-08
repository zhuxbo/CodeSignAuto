using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Text.RegularExpressions;

#if NET5_0_OR_GREATER
#pragma warning disable 8605
#pragma warning disable 8622
#pragma warning disable 8600
#pragma warning disable 8602
#pragma warning disable 8603
#endif

namespace CodeSignAuto.Acceptance.Contracts
{
    public sealed class AcceptanceContractException : Exception
    {
        public AcceptanceContractException(string code)
            : base(code)
        {
        }
    }

    public enum AcceptanceRunMode
    {
        FreshInstall,
        ExistingInstall
    }

    public static class AcceptanceModePolicy
    {
        public static AcceptanceRunMode Validate(string mode, bool hasApiTokenFile)
        {
            if (string.Equals(mode, "FreshInstall", StringComparison.Ordinal) && !hasApiTokenFile)
            {
                return AcceptanceRunMode.FreshInstall;
            }

            if (string.Equals(mode, "ExistingInstall", StringComparison.Ordinal) && hasApiTokenFile)
            {
                return AcceptanceRunMode.ExistingInstall;
            }

            throw new AcceptanceContractException("acceptance_mode_invalid");
        }
    }

    public static class SetupTokenFilePolicy
    {
        private static readonly Regex TokenPattern = new Regex(
            "^[A-Za-z0-9_-]{43}$",
            RegexOptions.CultureInvariant);

        public static string ValidateAndExtract(string tokenFileContent)
        {
            if (tokenFileContent == null)
            {
                throw new AcceptanceContractException("acceptance_install_token_invalid");
            }

            string token;
            if (tokenFileContent.EndsWith("\r\n", StringComparison.Ordinal))
            {
                token = tokenFileContent.Substring(0, tokenFileContent.Length - 2);
            }
            else if (tokenFileContent.EndsWith("\n", StringComparison.Ordinal))
            {
                token = tokenFileContent.Substring(0, tokenFileContent.Length - 1);
            }
            else
            {
                throw new AcceptanceContractException("acceptance_install_token_invalid");
            }

            if (!TokenPattern.IsMatch(token))
            {
                throw new AcceptanceContractException("acceptance_install_token_invalid");
            }

            return token;
        }
    }

    public static class InstallTokenCleanupPolicy
    {
        public static bool CanDelete(
            bool existedBefore,
            bool ownerAndAclExact,
            string expectedIdentity,
            string actualIdentity,
            string expectedSha256,
            string actualSha256,
            bool isReparse,
            bool isOrdinaryFile,
            int linkCount)
        {
            return !existedBefore &&
                ownerAndAclExact &&
                !string.IsNullOrEmpty(expectedIdentity) &&
                string.Equals(expectedIdentity, actualIdentity, StringComparison.Ordinal) &&
                AcceptanceInputPolicy.IsLowerHex(expectedSha256, 64) &&
                string.Equals(expectedSha256, actualSha256, StringComparison.Ordinal) &&
                !isReparse &&
                isOrdinaryFile &&
                linkCount == 1;
        }
    }

    public sealed class FailureCleanupPlan
    {
        public FailureCleanupPlan(
            bool requirePurgeUninstall,
            bool requireOneTimeTokenCleanup,
            bool requireFixtureCleanup)
        {
            RequirePurgeUninstall = requirePurgeUninstall;
            RequireOneTimeTokenCleanup = requireOneTimeTokenCleanup;
            RequireFixtureCleanup = requireFixtureCleanup;
        }

        public bool RequirePurgeUninstall { get; private set; }
        public bool RequireOneTimeTokenCleanup { get; private set; }
        public bool RequireFixtureCleanup { get; private set; }
        public bool PreserveFirstFailure { get { return true; } }
    }

    public static class FailureCleanupPolicy
    {
        public static FailureCleanupPlan Plan(
            bool freshInstall,
            bool installInvocationAttempted,
            bool oneTimeTokenObserved,
            bool fixtureInvocationAttempted)
        {
            return new FailureCleanupPlan(
                freshInstall && installInvocationAttempted,
                freshInstall && oneTimeTokenObserved,
                fixtureInvocationAttempted);
        }
    }

    public static class SentinelLayoutPolicy
    {
        public static void Validate(
            string fixtureRoot,
            string sentinelPath,
            string expectedIdentity,
            string actualIdentity,
            string expectedSha256,
            string actualSha256)
        {
            string root = Normalize(fixtureRoot);
            string sibling = Normalize(sentinelPath);
            int rootSeparator = root.LastIndexOf('\\');
            int siblingSeparator = sibling.LastIndexOf('\\');
            bool isSibling = rootSeparator > 2 &&
                siblingSeparator == rootSeparator &&
                string.Equals(
                    root.Substring(0, rootSeparator),
                    sibling.Substring(0, siblingSeparator),
                    StringComparison.OrdinalIgnoreCase);
            if (!isSibling ||
                sibling.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase) ||
                string.IsNullOrWhiteSpace(expectedIdentity) ||
                !string.Equals(expectedIdentity, actualIdentity, StringComparison.Ordinal) ||
                !AcceptanceInputPolicy.IsLowerHex(expectedSha256, 64) ||
                !string.Equals(expectedSha256, actualSha256, StringComparison.Ordinal))
            {
                throw new AcceptanceContractException("acceptance_fixture_sentinel_invalid");
            }
        }

        private static string Normalize(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            return value.Replace('/', '\\').TrimEnd('\\');
        }
    }

    public static class AcceptanceInputPolicy
    {
        private static readonly Regex CertificateSerialNumberPattern = new Regex(
            "^[0-9A-Fa-f]{2,128}$",
            RegexOptions.CultureInvariant);

        public static bool IsCertificateSerialNumber(string value)
        {
            return value != null && CertificateSerialNumberPattern.IsMatch(value);
        }

        public static bool IsTimeout(int seconds)
        {
            return seconds >= 60 && seconds <= 1800;
        }

        public static bool IsRunId(string value)
        {
            if (value == null || value.Length != 32)
            {
                return false;
            }

            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (!((character >= '0' && character <= '9') ||
                    (character >= 'a' && character <= 'f')))
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsUpperHex(string value, int exactLength)
        {
            if (value == null || value.Length != exactLength)
            {
                return false;
            }

            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (!((character >= '0' && character <= '9') ||
                    (character >= 'A' && character <= 'F')))
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsLowerHex(string value, int exactLength)
        {
            if (value == null || value.Length != exactLength)
            {
                return false;
            }

            for (int index = 0; index < value.Length; index++)
            {
                char character = value[index];
                if (!((character >= '0' && character <= '9') ||
                    (character >= 'a' && character <= 'f')))
                {
                    return false;
                }
            }

            return true;
        }
    }

    public sealed class WindowsSystemPublisherMap
    {
        private readonly Dictionary<string, string> publishers;

        internal WindowsSystemPublisherMap(Dictionary<string, string> publishers)
        {
            this.publishers = publishers;
        }

        public int Count
        {
            get { return publishers.Count; }
        }

        public string this[string toolId]
        {
            get
            {
                string publisher;
                if (toolId == null || !publishers.TryGetValue(toolId, out publisher))
                {
                    throw new AcceptanceContractException(
                        "acceptance_windows_system_publisher_map_invalid");
                }

                return publisher;
            }
        }

        public string ResolveExpectedPublisherSha256(string canonicalExecutablePath)
        {
            if (string.IsNullOrEmpty(canonicalExecutablePath) ||
                canonicalExecutablePath.Length > 1024 ||
                canonicalExecutablePath.IndexOfAny(new[] { '\r', '\n', '\0', '/' }) >= 0 ||
                !Regex.IsMatch(
                    canonicalExecutablePath,
                    "^[A-Za-z]:\\\\",
                    RegexOptions.CultureInvariant) ||
                canonicalExecutablePath.Substring(2).IndexOf(':') >= 0)
            {
                throw Invalid();
            }

            string[] segments = canonicalExecutablePath.Substring(3).Split(new[] { '\\' });
            if (segments.Length < 2 ||
                segments.Any(segment => string.IsNullOrEmpty(segment) ||
                    string.Equals(segment, ".", StringComparison.Ordinal) ||
                    string.Equals(segment, "..", StringComparison.Ordinal)))
            {
                throw Invalid();
            }

            string executableName = segments[segments.Length - 1];
            const string extension = ".exe";
            if (!executableName.EndsWith(extension, StringComparison.Ordinal))
            {
                throw Invalid();
            }

            string toolId = executableName.Substring(0, executableName.Length - extension.Length);
            string publisher;
            if (!publishers.TryGetValue(toolId, out publisher) ||
                !string.Equals(executableName, toolId + extension, StringComparison.Ordinal))
            {
                throw Invalid();
            }

            return publisher;
        }

        private static AcceptanceContractException Invalid()
        {
            return new AcceptanceContractException(
                "acceptance_windows_system_publisher_map_invalid");
        }
    }

    public static class WindowsSystemPublisherMapPolicy
    {
        private static readonly string[] ToolIds = new[]
        {
            "w32tm",
            "netsh",
            "sc",
            "taskkill",
            "tsdiscon",
            "tscon",
            "certutil"
        };

        private static readonly HashSet<string> ToolIdSet =
            new HashSet<string>(ToolIds, StringComparer.Ordinal);

        public static WindowsSystemPublisherMap Parse(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 1024)
            {
                throw Invalid();
            }

            string[] entries = value.Split(new[] { ';' }, StringSplitOptions.None);
            if (entries.Length != ToolIds.Length)
            {
                throw Invalid();
            }

            Dictionary<string, string> publishers =
                new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string entry in entries)
            {
                int separator = entry.IndexOf('=');
                if (separator <= 0 ||
                    separator != entry.LastIndexOf('=') ||
                    separator == entry.Length - 1)
                {
                    throw Invalid();
                }

                string toolId = entry.Substring(0, separator);
                string publisher = entry.Substring(separator + 1);
                if (!ToolIdSet.Contains(toolId) ||
                    !AcceptanceInputPolicy.IsLowerHex(publisher, 64) ||
                    publishers.ContainsKey(toolId))
                {
                    throw Invalid();
                }

                publishers.Add(toolId, publisher);
            }

            if (publishers.Count != ToolIds.Length ||
                ToolIds.Any(toolId => !publishers.ContainsKey(toolId)))
            {
                throw Invalid();
            }

            return new WindowsSystemPublisherMap(publishers);
        }

        private static AcceptanceContractException Invalid()
        {
            return new AcceptanceContractException(
                "acceptance_windows_system_publisher_map_invalid");
        }
    }

    public sealed class TimeSynchronizationEvidence
    {
        public TimeSynchronizationEvidence(
            bool serviceRunning,
            int queryExitCode,
            string localizedStatus,
            DateTimeOffset collectedAtUtc,
            DateTimeOffset latestValidDataUtc,
            DateTimeOffset latestFailureUtc,
            bool sourceIsLocalClock)
        {
            ServiceRunning = serviceRunning;
            QueryExitCode = queryExitCode;
            LocalizedStatus = localizedStatus;
            CollectedAtUtc = collectedAtUtc;
            LatestValidDataUtc = latestValidDataUtc;
            LatestFailureUtc = latestFailureUtc;
            SourceIsLocalClock = sourceIsLocalClock;
        }

        public bool ServiceRunning { get; private set; }
        public int QueryExitCode { get; private set; }
        public string LocalizedStatus { get; private set; }
        public DateTimeOffset CollectedAtUtc { get; private set; }
        public DateTimeOffset LatestValidDataUtc { get; private set; }
        public DateTimeOffset LatestFailureUtc { get; private set; }
        public bool SourceIsLocalClock { get; private set; }
    }

    public static class TimeSynchronizationPolicy
    {
        private static readonly TimeSpan MaximumValidDataAge = TimeSpan.FromHours(2);
        private static readonly TimeSpan MaximumFutureSkew = TimeSpan.FromMinutes(5);

        public static void Validate(TimeSynchronizationEvidence evidence)
        {
            if (evidence == null ||
                !evidence.ServiceRunning ||
                evidence.QueryExitCode != 0 ||
                evidence.CollectedAtUtc == DateTimeOffset.MinValue ||
                evidence.LatestValidDataUtc == DateTimeOffset.MinValue ||
                evidence.SourceIsLocalClock ||
                evidence.LatestValidDataUtc > evidence.CollectedAtUtc + MaximumFutureSkew ||
                evidence.CollectedAtUtc - evidence.LatestValidDataUtc > MaximumValidDataAge ||
                (evidence.LatestFailureUtc != DateTimeOffset.MinValue &&
                    evidence.LatestFailureUtc >= evidence.LatestValidDataUtc))
            {
                throw new AcceptanceContractException("acceptance_time_unsynchronized");
            }
        }
    }

    public static class PdfDualValidationPolicy
    {
        public static void Validate(
            bool projectValidatorOk,
            int independentExitCode,
            string independentOutput,
            bool documentChainValid,
            bool timestampChainValid)
        {
            string normalized = independentOutput == null
                ? string.Empty
                : independentOutput.Replace("\r\n", "\n");
            if (!projectValidatorOk ||
                independentExitCode != 0 ||
                !(string.Equals(normalized, "VALID", StringComparison.Ordinal) ||
                    string.Equals(normalized, "VALID\n", StringComparison.Ordinal)) ||
                !documentChainValid ||
                !timestampChainValid)
            {
                throw new AcceptanceContractException("acceptance_pdf_dual_validation_failed");
            }
        }
    }

    public static class SignatureTimestampPolicy
    {
        public static void Validate(
            string timestampUtc,
            DateTimeOffset acceptanceStartedUtc,
            DateTimeOffset validationCompletedUtc,
            string actualTsaSha256,
            string expectedTsaSha256,
            string actualTsaSubject,
            string expectedTsaSubjectSuffix)
        {
            DateTimeOffset observed = ReadAndValidateSignerIdentity(
                timestampUtc,
                actualTsaSha256,
                expectedTsaSha256,
                actualTsaSubject,
                expectedTsaSubjectSuffix);
            if (validationCompletedUtc < acceptanceStartedUtc ||
                observed < acceptanceStartedUtc.AddMinutes(-5) ||
                observed > validationCompletedUtc.AddMinutes(5))
            {
                throw new AcceptanceContractException("acceptance_timestamp_invalid");
            }
        }

        public static void ValidateSignerIdentity(
            string timestampUtc,
            string actualTsaSha256,
            string expectedTsaSha256,
            string actualTsaSubject,
            string expectedTsaSubjectSuffix)
        {
            ReadAndValidateSignerIdentity(
                timestampUtc,
                actualTsaSha256,
                expectedTsaSha256,
                actualTsaSubject,
                expectedTsaSubjectSuffix);
        }

        private static DateTimeOffset ReadAndValidateSignerIdentity(
            string timestampUtc,
            string actualTsaSha256,
            string expectedTsaSha256,
            string actualTsaSubject,
            string expectedTsaSubjectSuffix)
        {
            DateTimeOffset observed;
            bool timestampParsed = DateTimeOffset.TryParseExact(
                timestampUtc,
                "yyyy-MM-dd'T'HH:mm:ss'Z'",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out observed);
            if (!timestampParsed ||
                !AcceptanceInputPolicy.IsLowerHex(actualTsaSha256, 64) ||
                !AcceptanceInputPolicy.IsLowerHex(expectedTsaSha256, 64) ||
                !string.Equals(actualTsaSha256, expectedTsaSha256, StringComparison.Ordinal) ||
                string.IsNullOrEmpty(actualTsaSubject) ||
                string.IsNullOrEmpty(expectedTsaSubjectSuffix) ||
                !actualTsaSubject.EndsWith(expectedTsaSubjectSuffix, StringComparison.Ordinal))
            {
                throw new AcceptanceContractException("acceptance_timestamp_invalid");
            }

            return observed;
        }
    }

    public sealed class ReloginTransitionSnapshot
    {
        public ReloginTransitionSnapshot(
            long sequence,
            string state,
            long sessionGeneration,
            DateTimeOffset transitionedAtUtc,
            int attempt)
        {
            Sequence = sequence;
            State = state;
            SessionGeneration = sessionGeneration;
            TransitionedAtUtc = transitionedAtUtc;
            Attempt = attempt;
        }

        public long Sequence { get; private set; }
        public string State { get; private set; }
        public long SessionGeneration { get; private set; }
        public DateTimeOffset TransitionedAtUtc { get; private set; }
        public int Attempt { get; private set; }
    }

    public static class UnattendedReloginEvidencePolicy
    {
        private static readonly string[] ExpectedStates = new[]
        {
            "UNKNOWN",
            "CHECKING",
            "LOGIN_REQUIRED",
            "LOGINNING",
            "WAIT_TOKEN",
            "READY"
        };

        private static readonly HashSet<string> AllowedStates = new HashSet<string>(
            new[]
            {
                "UNKNOWN",
                "CHECKING",
                "READY",
                "LOGIN_REQUIRED",
                "LOGINNING",
                "WAIT_TOKEN",
                "FAILED"
            },
            StringComparer.Ordinal);

        public static void Validate(
            int agentPidBeforeClose,
            int agentPidAfterClose,
            bool agentAliveAfterClose,
            DateTimeOffset closedAtUtc,
            long readyGeneration,
            IEnumerable<ReloginTransitionSnapshot> transitions,
            string configuredTransport,
            string codeJobTransport,
            string pdfJobTransport,
            bool codeSignatureVerified,
            bool pdfSignatureVerified)
        {
            ReloginTransitionSnapshot[] observed = transitions == null
                ? new ReloginTransitionSnapshot[0]
                : transitions.ToArray();
            if (agentPidBeforeClose <= 0 ||
                agentPidAfterClose != agentPidBeforeClose ||
                !agentAliveAfterClose ||
                closedAtUtc == default(DateTimeOffset) ||
                closedAtUtc.Offset != TimeSpan.Zero ||
                readyGeneration <= 0 ||
                observed.Length == 0 ||
                observed.Length > 64 ||
                (configuredTransport != "http" && configuredTransport != "https") ||
                !string.Equals(codeJobTransport, configuredTransport, StringComparison.Ordinal) ||
                !string.Equals(pdfJobTransport, configuredTransport, StringComparison.Ordinal) ||
                !codeSignatureVerified ||
                !pdfSignatureVerified ||
                !ValidOrderedEvidence(observed, readyGeneration))
            {
                throw Invalid();
            }

            ReloginTransitionSnapshot[] recovery = observed
                .Where(item =>
                    item.SessionGeneration == readyGeneration &&
                    item.TransitionedAtUtc >= closedAtUtc)
                .OrderBy(item => item.Sequence)
                .ToArray();
            if (recovery.Length != ExpectedStates.Length ||
                !recovery.Select(item => item.State).SequenceEqual(ExpectedStates, StringComparer.Ordinal) ||
                observed.Count(item =>
                    item.SessionGeneration == readyGeneration &&
                    item.TransitionedAtUtc >= closedAtUtc &&
                    string.Equals(item.State, "LOGINNING", StringComparison.Ordinal)) != 1)
            {
                throw Invalid();
            }
        }

        private static bool ValidOrderedEvidence(
            IReadOnlyList<ReloginTransitionSnapshot> transitions,
            long readyGeneration)
        {
            long previousSequence = 0;
            long previousGeneration = 0;
            foreach (ReloginTransitionSnapshot item in transitions)
            {
                if (item == null ||
                    item.Sequence <= previousSequence ||
                    !AllowedStates.Contains(item.State) ||
                    item.SessionGeneration <= 0 ||
                    item.SessionGeneration > readyGeneration ||
                    item.TransitionedAtUtc == default(DateTimeOffset) ||
                    item.TransitionedAtUtc.Offset != TimeSpan.Zero ||
                    item.Attempt < 0 ||
                    item.Attempt > 2 ||
                    item.SessionGeneration < previousGeneration)
                {
                    return false;
                }

                previousSequence = item.Sequence;
                previousGeneration = item.SessionGeneration;
            }

            return true;
        }
        private static AcceptanceContractException Invalid()
        {
            return new AcceptanceContractException("acceptance_unattended_relogin_invalid");
        }
    }

    public static class PurgeBootEvidencePolicy
    {
        public static void Validate(
            string operationId,
            IEnumerable<string> stagingVolumes,
            DateTimeOffset bootBefore,
            DateTimeOffset bootAfter,
            bool sourceRootsIsolated,
            bool manifestRemoved,
            bool cleanupTaskRemoved,
            bool stagingRootsRemoved,
            bool resumeTaskOwnerExact)
        {
            string[] volumes = stagingVolumes == null
                ? new string[0]
                : stagingVolumes.ToArray();
            if (!AcceptanceInputPolicy.IsRunId(operationId) ||
                volumes.Length != 1 ||
                volumes.Any(string.IsNullOrWhiteSpace) ||
                bootAfter <= bootBefore ||
                !sourceRootsIsolated ||
                !manifestRemoved ||
                !cleanupTaskRemoved ||
                !stagingRootsRemoved ||
                !resumeTaskOwnerExact)
            {
                throw new AcceptanceContractException("acceptance_purge_boot_invalid");
            }
        }
    }

    public static class PurgeHardStopEvidencePolicy
    {
        public static void Validate(
            string expectedOperationId,
            string actualOperationId,
            IEnumerable<string> expectedSourcePaths,
            IEnumerable<string> actualSourcePaths,
            IEnumerable<string> expectedStagedPaths,
            IEnumerable<string> actualStagedPaths,
            int stagedTargetCountAtTermination,
            bool cleanupTaskAbsentAtTermination,
            bool processTreeTerminated,
            bool checkpointSecretScanClean,
            bool rootUninstallResumed,
            bool exactOwnedProductRemoved,
            bool exactOwnedUserRemoved,
            bool exactOwnedProfileRemoved,
            bool simplySignDesktopPreserved,
            bool pkcs11Preserved,
            bool desktopRuntimePreserved,
            bool aspNetCoreRuntimePreserved)
        {
            string[] expectedSources = Values(expectedSourcePaths);
            string[] actualSources = Values(actualSourcePaths);
            string[] expectedStaged = Values(expectedStagedPaths);
            string[] actualStaged = Values(actualStagedPaths);
            if (!AcceptanceInputPolicy.IsRunId(expectedOperationId) ||
                !string.Equals(expectedOperationId, actualOperationId, StringComparison.Ordinal) ||
                expectedSources.Length != 1 ||
                expectedStaged.Length != expectedSources.Length ||
                !EqualPaths(expectedSources, actualSources) ||
                !EqualPaths(expectedStaged, actualStaged) ||
                expectedSources.Distinct(StringComparer.OrdinalIgnoreCase).Count() != expectedSources.Length ||
                expectedStaged.Distinct(StringComparer.OrdinalIgnoreCase).Count() != expectedStaged.Length ||
                stagedTargetCountAtTermination != 1 ||
                !cleanupTaskAbsentAtTermination ||
                !processTreeTerminated ||
                !checkpointSecretScanClean ||
                !rootUninstallResumed ||
                !exactOwnedProductRemoved ||
                !exactOwnedUserRemoved ||
                !exactOwnedProfileRemoved ||
                !simplySignDesktopPreserved ||
                !pkcs11Preserved ||
                !desktopRuntimePreserved ||
                !aspNetCoreRuntimePreserved)
            {
                throw new AcceptanceContractException("acceptance_purge_hard_stop_invalid");
            }
        }

        private static string[] Values(IEnumerable<string> values) =>
            values == null ? new string[0] : values.ToArray();

        private static bool EqualPaths(string[] expected, string[] actual) =>
            expected.Length == actual.Length &&
            expected.Zip(actual, (left, right) =>
                !string.IsNullOrWhiteSpace(left) &&
                string.Equals(left, right, StringComparison.OrdinalIgnoreCase)).All(equal => equal);
    }

    public static class UnattendedRebootEvidencePolicy
    {
        private static readonly Regex SidPattern = new Regex(
            "^S-1-[0-9]+(?:-[0-9]+)+$",
            RegexOptions.CultureInvariant);

        public static void Validate(
            DateTimeOffset bootBefore,
            DateTimeOffset bootAfter,
            int signingSessionId,
            string expectedSigningSid,
            string actualSigningSid,
            int wtsClientProtocol,
            bool agentTaskExact,
            bool agentTaskRunning,
            int agentProcessId,
            int agentProcessSessionId,
            int heartbeatAgeSeconds,
            int readyElapsedSeconds,
            bool authenticodeReady,
            bool pdfReady,
            bool authenticodeVerified,
            bool pdfVerified)
        {
            if (bootBefore == default(DateTimeOffset) ||
                bootAfter <= bootBefore ||
                signingSessionId <= 0 ||
                !SidPattern.IsMatch(expectedSigningSid ?? string.Empty) ||
                !string.Equals(expectedSigningSid, actualSigningSid, StringComparison.Ordinal) ||
                wtsClientProtocol != 0 ||
                !agentTaskExact ||
                !agentTaskRunning ||
                agentProcessId <= 0 ||
                agentProcessSessionId != signingSessionId ||
                heartbeatAgeSeconds < 0 ||
                heartbeatAgeSeconds > 15 ||
                readyElapsedSeconds < 0 ||
                readyElapsedSeconds > 300 ||
                !authenticodeReady ||
                !pdfReady ||
                !authenticodeVerified ||
                !pdfVerified)
            {
                throw new AcceptanceContractException("acceptance_unattended_reboot_invalid");
            }
        }
    }

    public static class UnattendedRebootCleanupPolicy
    {
        private static readonly Regex RunIdPattern = new Regex(
            "^[0-9a-f]{32}$",
            RegexOptions.CultureInvariant);
        private static readonly Regex FailurePattern = new Regex(
            "^acceptance_[a-z0-9_]+$",
            RegexOptions.CultureInvariant);

        public static string Resolve(
            string firstFailure,
            string runId,
            string lsaKey,
            bool secretStored,
            bool secretAbsent,
            string taskName,
            bool taskRegistered,
            bool taskOwnershipExact,
            bool taskAbsent)
        {
            bool identityExact = IsIdentityExact(runId, lsaKey, taskName);
            bool cleanupExact = (!secretStored || secretAbsent) &&
                (!taskRegistered || (taskOwnershipExact && taskAbsent));
            if (!identityExact || !cleanupExact)
            {
                return "acceptance_state_uncertain";
            }

            if (firstFailure == null)
            {
                return null;
            }

            return FailurePattern.IsMatch(firstFailure)
                ? firstFailure
                : "acceptance_state_uncertain";
        }

        public static bool IsIdentityExact(string runId, string lsaKey, string taskName)
        {
            return runId != null &&
                RunIdPattern.IsMatch(runId) &&
                string.Equals(
                    lsaKey,
                    "CodeSignAuto/Acceptance/" + runId + "/Api",
                    StringComparison.Ordinal) &&
                string.Equals(
                    taskName,
                    "CodeSignAuto.Acceptance.Boot." + runId,
                    StringComparison.Ordinal);
        }
    }

    public sealed class BootResumeTaskSnapshot
    {
        public BootResumeTaskSnapshot(
            string userId,
            string logonType,
            string runLevel,
            string executeHash,
            string argumentsHash,
            string trigger,
            string source,
            string ownerMarker,
            int executionLimitSeconds,
            int actionCount)
        {
            UserId = userId;
            LogonType = logonType;
            RunLevel = runLevel;
            ExecuteHash = executeHash;
            ArgumentsHash = argumentsHash;
            Trigger = trigger;
            Source = source;
            OwnerMarker = ownerMarker;
            ExecutionLimitSeconds = executionLimitSeconds;
            ActionCount = actionCount;
        }

        public string UserId { get; private set; }
        public string LogonType { get; private set; }
        public string RunLevel { get; private set; }
        public string ExecuteHash { get; private set; }
        public string ArgumentsHash { get; private set; }
        public string Trigger { get; private set; }
        public string Source { get; private set; }
        public string OwnerMarker { get; private set; }
        public int ExecutionLimitSeconds { get; private set; }
        public int ActionCount { get; private set; }
    }

    public static class BootResumeTaskPolicy
    {
        public static void Validate(BootResumeTaskSnapshot expected, BootResumeTaskSnapshot actual)
        {
            if (expected == null || actual == null ||
                !string.Equals(expected.UserId, "S-1-5-18", StringComparison.Ordinal) ||
                !string.Equals(expected.LogonType, "ServiceAccount", StringComparison.Ordinal) ||
                !string.Equals(expected.RunLevel, "Highest", StringComparison.Ordinal) ||
                !string.Equals(expected.Trigger, "AtStartup", StringComparison.Ordinal) ||
                !string.Equals(expected.Source, "CodeSignAuto/v1", StringComparison.Ordinal) ||
                !string.Equals(expected.OwnerMarker, "CodeSignAuto/AcceptanceBoot/v1", StringComparison.Ordinal) ||
                expected.ExecutionLimitSeconds < 60 ||
                expected.ExecutionLimitSeconds > 1800 ||
                expected.ActionCount != 1 ||
                !Equal(expected, actual))
            {
                throw new AcceptanceContractException("acceptance_boot_task_invalid");
            }
        }

        private static bool Equal(BootResumeTaskSnapshot left, BootResumeTaskSnapshot right)
        {
            return string.Equals(left.UserId, right.UserId, StringComparison.Ordinal) &&
                string.Equals(left.LogonType, right.LogonType, StringComparison.Ordinal) &&
                string.Equals(left.RunLevel, right.RunLevel, StringComparison.Ordinal) &&
                string.Equals(left.ExecuteHash, right.ExecuteHash, StringComparison.Ordinal) &&
                string.Equals(left.ArgumentsHash, right.ArgumentsHash, StringComparison.Ordinal) &&
                string.Equals(left.Trigger, right.Trigger, StringComparison.Ordinal) &&
                string.Equals(left.Source, right.Source, StringComparison.Ordinal) &&
                string.Equals(left.OwnerMarker, right.OwnerMarker, StringComparison.Ordinal) &&
                left.ExecutionLimitSeconds == right.ExecutionLimitSeconds &&
                left.ActionCount == right.ActionCount;
        }
    }

    public static class RemoteAcceptanceMatrixPolicy
    {
        private static readonly string[] NativeExtensions =
            new[] { ".msi", ".cat", ".sys", ".dll" };

        public static void ValidateSignerSequence(
            IEnumerable<string> actual,
            IEnumerable<string> expected)
        {
            string[] actualValues = actual == null ? new string[0] : actual.ToArray();
            string[] expectedValues = expected == null ? new string[0] : expected.ToArray();
            if (actualValues.Length != expectedValues.Length ||
                actualValues.Length < 1)
            {
                throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
            }

            for (int index = 0; index < expectedValues.Length; index++)
            {
                if (!AcceptanceInputPolicy.IsUpperHex(actualValues[index], 8) ||
                    !AcceptanceInputPolicy.IsUpperHex(expectedValues[index], 8) ||
                    !string.Equals(actualValues[index], expectedValues[index], StringComparison.Ordinal))
                {
                    throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
                }
            }
        }

        public static void ValidateNativeFixtureSlots(IEnumerable<string> extensions)
        {
            string[] actual = extensions == null ? new string[0] : extensions.ToArray();
            if (actual.Length != NativeExtensions.Length)
            {
                throw new AcceptanceContractException("acceptance_native_fixture_invalid");
            }

            for (int index = 0; index < NativeExtensions.Length; index++)
            {
                if (!string.Equals(actual[index], NativeExtensions[index], StringComparison.Ordinal))
                {
                    throw new AcceptanceContractException("acceptance_native_fixture_invalid");
                }
            }
        }

        public static void ValidateQueueRecovery(
            IEnumerable<string> submitted,
            IEnumerable<string> observedWaiting,
            IEnumerable<string> completed,
            int observedMaximumActive,
            string idempotentOriginal,
            string idempotentRetry,
            bool changedInputConflict,
            bool serviceRestartObserved,
            bool agentRecoveryObserved)
        {
            string[] submittedValues = submitted == null ? new string[0] : submitted.ToArray();
            string[] waitingValues = observedWaiting == null ? new string[0] : observedWaiting.ToArray();
            string[] completedValues = completed == null ? new string[0] : completed.ToArray();
            if (!IsExactFiveUnique(submittedValues) ||
                !SequenceEqualOrdinal(submittedValues, waitingValues) ||
                !SequenceEqualOrdinal(submittedValues, completedValues) ||
                observedMaximumActive != 1 ||
                string.IsNullOrEmpty(idempotentOriginal) ||
                !string.Equals(idempotentOriginal, idempotentRetry, StringComparison.Ordinal) ||
                !changedInputConflict ||
                !serviceRestartObserved ||
                !agentRecoveryObserved)
            {
                throw new AcceptanceContractException("acceptance_queue_recovery_invalid");
            }
        }

        public static void ValidateProductionQuickSign(
            string exeInputBefore,
            string exeInputAfter,
            string exeResult,
            string pdfInputBefore,
            string pdfInputAfter,
            string pdfResult,
            bool productionComposition,
            bool readinessVisible,
            bool hiddenSubmissionCompleted,
            bool trayRestoreObserved,
            bool secretScanClean)
        {
            string[] hashes = new[]
            {
                exeInputBefore,
                exeInputAfter,
                exeResult,
                pdfInputBefore,
                pdfInputAfter,
                pdfResult,
            };
            if (hashes.Any(value => !AcceptanceInputPolicy.IsUpperHex(value, 64)) ||
                !string.Equals(exeInputBefore, exeInputAfter, StringComparison.Ordinal) ||
                !string.Equals(pdfInputBefore, pdfInputAfter, StringComparison.Ordinal) ||
                string.Equals(exeInputBefore, exeResult, StringComparison.Ordinal) ||
                string.Equals(pdfInputBefore, pdfResult, StringComparison.Ordinal) ||
                !productionComposition ||
                !readinessVisible ||
                !hiddenSubmissionCompleted ||
                !trayRestoreObserved ||
                !secretScanClean)
            {
                throw new AcceptanceContractException("acceptance_production_ui_invalid");
            }
        }

        public static void ValidateFailureSessionAndBootMatrix(
            bool unauthorizedIs401,
            bool corruptPdfRejectedWithoutResult,
            bool autoReloginAfterClose,
            bool disconnectedSessionUnavailable,
            bool sessionZeroUnavailable,
            bool activeSessionRecovered,
            bool managedPurgeObserved,
            bool rebootCleanupResumed,
            bool pssaClean,
            bool timeSynchronized,
            bool urlAclExact)
        {
            if (!unauthorizedIs401 ||
                !corruptPdfRejectedWithoutResult ||
                !autoReloginAfterClose ||
                !disconnectedSessionUnavailable ||
                !sessionZeroUnavailable ||
                !activeSessionRecovered ||
                !managedPurgeObserved ||
                !rebootCleanupResumed ||
                !pssaClean ||
                !timeSynchronized ||
                !urlAclExact)
            {
                throw new AcceptanceContractException("acceptance_remote_matrix_incomplete");
            }
        }

        private static bool IsExactFiveUnique(string[] values)
        {
            if (values.Length != 5)
            {
                return false;
            }

            HashSet<string> unique = new HashSet<string>(StringComparer.Ordinal);
            return values.All(value => !string.IsNullOrEmpty(value) && unique.Add(value));
        }

        private static bool SequenceEqualOrdinal(string[] expected, string[] actual)
        {
            if (expected.Length != actual.Length)
            {
                return false;
            }

            for (int index = 0; index < expected.Length; index++)
            {
                if (!string.Equals(expected[index], actual[index], StringComparison.Ordinal))
                {
                    return false;
                }
            }

            return true;
        }
    }

    public enum NativeFixtureSourceMode
    {
        AutoGenerated,
        ExplicitOverride
    }

    public static class NativeFixtureSourcePolicy
    {
        public static NativeFixtureSourceMode Plan(
            string msi,
            string cat,
            string sys,
            string dll)
        {
            string[] values = new[] { msi, cat, sys, dll };
            bool[] present = values
                .Select(value => !string.IsNullOrWhiteSpace(value))
                .ToArray();
            if (present.All(value => !value))
            {
                return NativeFixtureSourceMode.AutoGenerated;
            }

            if (!present.All(value => value))
            {
                throw new AcceptanceContractException("acceptance_native_fixture_invalid");
            }

            RemoteAcceptanceMatrixPolicy.ValidateNativeFixtureSlots(
                values.Select(value => System.IO.Path.GetExtension(value).ToLowerInvariant()));
            return NativeFixtureSourceMode.ExplicitOverride;
        }

        public static void ValidateToolPublisherHashes(
            NativeFixtureSourceMode mode,
            string makeCatSha256,
            string cscSha256,
            string driverSha256)
        {
            if (mode == NativeFixtureSourceMode.ExplicitOverride)
            {
                return;
            }

            if (mode != NativeFixtureSourceMode.AutoGenerated ||
                !AcceptanceInputPolicy.IsLowerHex(makeCatSha256, 64) ||
                !AcceptanceInputPolicy.IsLowerHex(cscSha256, 64) ||
                !AcceptanceInputPolicy.IsLowerHex(driverSha256, 64))
            {
                throw new AcceptanceContractException("acceptance_native_fixture_tool_invalid");
            }
        }

        public static void ValidateFixtureHashes(
            NativeFixtureSourceMode mode,
            string msiSha256,
            string catSha256,
            string sysSha256,
            string dllSha256)
        {
            string[] hashes = new[] { msiSha256, catSha256, sysSha256, dllSha256 };
            if (mode == NativeFixtureSourceMode.AutoGenerated &&
                hashes.All(string.IsNullOrWhiteSpace))
            {
                return;
            }

            if (mode == NativeFixtureSourceMode.ExplicitOverride &&
                hashes.All(value => AcceptanceInputPolicy.IsLowerHex(value, 64)))
            {
                return;
            }

            throw new AcceptanceContractException("acceptance_native_fixture_invalid");
        }
    }

    public static class NativeTestRoutingPolicy
    {
        private static readonly string[] InteractiveTests = new[]
        {
            "CodeSignAuto.Agent.Tests.DpapiOtpStoreTests.Protects_file_acl_for_current_user_and_system_only",
            "CodeSignAuto.Agent.Tests.DpapiOtpStoreTests.Reports_corrupt_when_ciphertext_is_tampered",
            "CodeSignAuto.Agent.Tests.DpapiOtpStoreTests.Saves_and_loads_for_current_windows_user",
            "CodeSignAuto.Agent.Tests.DpapiOtpStoreTests.Reports_missing_for_missing_file",
            "CodeSignAuto.Agent.Tests.AgentHostTests.Windows_local_mutex_rejects_a_second_owner_for_the_same_sid",
            "CodeSignAuto.Agent.Tests.AgentHostTests.Windows_local_mutex_lease_can_be_disposed_from_a_different_thread",
            "CodeSignAuto.Agent.Tests.AgentHostTests.Windows_session_ending_monitor_can_start_and_stop_its_hidden_window",
            "CodeSignAuto.Service.Tests.WindowsSpoolAclPolicyTests.Windows_signing_user_can_delete_only_the_part_it_created",
            "CodeSignAuto.UI.Tests.WindowsDesktopIntegrationTests.Wpf_runtime_preserves_theme_icon_tray_and_opens_settings_on_its_visible_main_window",
            "CodeSignAuto.UI.Tests.WindowsDesktopIntegrationTests.Activation_pipe_is_exclusive_and_accepts_only_the_current_signing_user",
            "CodeSignAuto.UI.Tests.WindowsDesktopIntegrationTests.A_preexisting_pipe_squatter_cannot_be_claimed_and_never_starts_the_agent",
        };

        private static readonly HashSet<string> InteractiveSet =
            new HashSet<string>(InteractiveTests, StringComparer.Ordinal);

        public static string[] GetInteractiveTests()
        {
            return (string[])InteractiveTests.Clone();
        }

        public static bool IsInteractive(string testName)
        {
            return testName != null && InteractiveSet.Contains(testName);
        }
    }

    public enum ExecutableTrustKind
    {
        PlatformPublisher,
        ManifestSha256
    }

    public sealed class ExecutableTrustSnapshot
    {
        public ExecutableTrustSnapshot(
            string path,
            string identity,
            string sha256,
            bool isOrdinaryFile,
            bool isReparse,
            bool ownerProtected,
            bool daclProtected,
            bool ancestorsProtected,
            bool signatureValid,
            string publisherSha256)
        {
            Path = path;
            Identity = identity;
            Sha256 = sha256;
            IsOrdinaryFile = isOrdinaryFile;
            IsReparse = isReparse;
            OwnerProtected = ownerProtected;
            DaclProtected = daclProtected;
            AncestorsProtected = ancestorsProtected;
            SignatureValid = signatureValid;
            PublisherSha256 = publisherSha256;
        }

        public string Path { get; private set; }
        public string Identity { get; private set; }
        public string Sha256 { get; private set; }
        public bool IsOrdinaryFile { get; private set; }
        public bool IsReparse { get; private set; }
        public bool OwnerProtected { get; private set; }
        public bool DaclProtected { get; private set; }
        public bool AncestorsProtected { get; private set; }
        public bool SignatureValid { get; private set; }
        public string PublisherSha256 { get; private set; }
    }

    public static class TrustedExecutablePolicy
    {
        public static void Validate(
            ExecutableTrustSnapshot before,
            ExecutableTrustSnapshot after,
            IEnumerable<string> trustedRoots,
            ExecutableTrustKind trustKind,
            string expectedPublisherOrManifestSha256)
        {
            if (!IsTrustedInitialSnapshot(
                    before,
                    trustedRoots,
                    trustKind,
                    expectedPublisherOrManifestSha256))
            {
                throw new AcceptanceContractException("acceptance_executable_untrusted");
            }

            if (after == null ||
                !string.Equals(before.Path, after.Path, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(before.Identity, after.Identity, StringComparison.Ordinal) ||
                !string.Equals(before.Sha256, after.Sha256, StringComparison.Ordinal) ||
                !after.IsOrdinaryFile ||
                after.IsReparse ||
                !after.OwnerProtected ||
                !after.DaclProtected ||
                !after.AncestorsProtected)
            {
                throw new AcceptanceContractException("acceptance_executable_changed");
            }
        }

        public static bool IsWithinTrustedRoot(string path, IEnumerable<string> trustedRoots)
        {
            string normalizedPath;
            if (!TryNormalizeAbsoluteWindowsPath(path, out normalizedPath) || trustedRoots == null)
            {
                return false;
            }

            foreach (string root in trustedRoots)
            {
                string normalizedRoot;
                if (!TryNormalizeAbsoluteWindowsPath(root, out normalizedRoot))
                {
                    continue;
                }

                normalizedRoot = normalizedRoot.TrimEnd('\\');
                if (normalizedRoot.Length == 2)
                {
                    normalizedRoot += "\\";
                }

                string boundary = normalizedRoot.EndsWith("\\", StringComparison.Ordinal)
                    ? normalizedRoot
                    : normalizedRoot + "\\";
                if (normalizedPath.StartsWith(boundary, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsTrustedInitialSnapshot(
            ExecutableTrustSnapshot snapshot,
            IEnumerable<string> trustedRoots,
            ExecutableTrustKind trustKind,
            string expected)
        {
            if (snapshot == null ||
                !snapshot.IsOrdinaryFile ||
                snapshot.IsReparse ||
                !snapshot.OwnerProtected ||
                !snapshot.DaclProtected ||
                !snapshot.AncestorsProtected ||
                string.IsNullOrEmpty(snapshot.Identity) ||
                !AcceptanceInputPolicy.IsLowerHex(snapshot.Sha256, 64) ||
                !AcceptanceInputPolicy.IsLowerHex(expected, 64) ||
                !IsWithinTrustedRoot(snapshot.Path, trustedRoots))
            {
                return false;
            }

            if (trustKind == ExecutableTrustKind.PlatformPublisher)
            {
                return snapshot.SignatureValid &&
                    AcceptanceInputPolicy.IsLowerHex(snapshot.PublisherSha256, 64) &&
                    string.Equals(snapshot.PublisherSha256, expected, StringComparison.Ordinal);
            }

            return trustKind == ExecutableTrustKind.ManifestSha256 &&
                string.Equals(snapshot.Sha256, expected, StringComparison.Ordinal);
        }

        private static bool TryNormalizeAbsoluteWindowsPath(string value, out string normalized)
        {
            normalized = string.Empty;
            if (string.IsNullOrEmpty(value) ||
                value.Length > 1024 ||
                value.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0 ||
                !Regex.IsMatch(value, "^[A-Za-z]:[\\\\/]", RegexOptions.CultureInvariant))
            {
                return false;
            }

            string candidate = value.Replace('/', '\\');
            string[] segments = candidate.Substring(3).Split(new[] { '\\' });
            if (segments.Any(segment => segment.Length == 0 ||
                string.Equals(segment, ".", StringComparison.Ordinal) ||
                string.Equals(segment, "..", StringComparison.Ordinal)))
            {
                return false;
            }

            normalized = char.ToUpperInvariant(candidate[0]) + candidate.Substring(1);
            return true;
        }
    }

    public sealed class SidSessionCandidate
    {
        public SidSessionCandidate(int sessionId, string state, string principalSid)
        {
            SessionId = sessionId;
            State = state;
            PrincipalSid = principalSid;
        }

        public int SessionId { get; private set; }
        public string State { get; private set; }
        public string PrincipalSid { get; private set; }
    }

    public static class SidSessionSelectionPolicy
    {
        private static readonly Regex SidPattern = new Regex(
            "^S-1-[0-9]+(?:-[0-9]+)+$",
            RegexOptions.CultureInvariant);

        public static int SelectUniqueActive(
            IEnumerable<SidSessionCandidate> candidates,
            string expectedPrincipalSid)
        {
            if (candidates == null ||
                expectedPrincipalSid == null ||
                !SidPattern.IsMatch(expectedPrincipalSid))
            {
                throw new AcceptanceContractException("acceptance_session_unavailable");
            }

            int selected = 0;
            int count = 0;
            foreach (SidSessionCandidate candidate in candidates)
            {
                if (candidate != null &&
                    candidate.SessionId > 0 &&
                    string.Equals(candidate.State, "Active", StringComparison.Ordinal) &&
                    string.Equals(candidate.PrincipalSid, expectedPrincipalSid, StringComparison.Ordinal))
                {
                    selected = candidate.SessionId;
                    count++;
                }
            }

            if (count != 1)
            {
                throw new AcceptanceContractException("acceptance_session_unavailable");
            }

            return selected;
        }
    }

    public static class UiArtifactAclPolicy
    {
        public static void Validate(
            bool topLevelSigningUserCanModify,
            bool uiRootSigningUserCanModify,
            bool beforeReadbackExact,
            bool afterReadbackExact)
        {
            if (topLevelSigningUserCanModify ||
                !uiRootSigningUserCanModify ||
                !beforeReadbackExact ||
                !afterReadbackExact)
            {
                throw new AcceptanceContractException("acceptance_ui_acl_invalid");
            }
        }
    }

    public sealed class AgentTaskTriggerXmlSnapshot
    {
        public AgentTaskTriggerXmlSnapshot(string kind, int childCount)
        {
            Kind = kind;
            ChildCount = childCount;
        }

        public string Kind { get; private set; }
        public int ChildCount { get; private set; }
    }

    public static class AgentTaskTriggerXmlPolicy
    {
        private const string TaskNamespace = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        public static AgentTaskTriggerXmlSnapshot Read(string xml)
        {
            if (string.IsNullOrWhiteSpace(xml) || xml.Length > 262144)
            {
                throw Invalid();
            }

            var settings = new System.Xml.XmlReaderSettings();
            settings.DtdProcessing = System.Xml.DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            var document = new System.Xml.XmlDocument();
            document.XmlResolver = null;
            try
            {
                using (var text = new System.IO.StringReader(xml))
                using (var reader = System.Xml.XmlReader.Create(text, settings))
                {
                    document.Load(reader);
                }
            }
            catch
            {
                throw Invalid();
            }

            System.Xml.XmlElement root = document.DocumentElement;
            if (root == null ||
                !string.Equals(root.LocalName, "Task", StringComparison.Ordinal) ||
                !string.Equals(root.NamespaceURI, TaskNamespace, StringComparison.Ordinal))
            {
                throw Invalid();
            }

            var namespaces = new System.Xml.XmlNamespaceManager(document.NameTable);
            namespaces.AddNamespace("t", TaskNamespace);
            System.Xml.XmlNodeList containers = root.SelectNodes("./t:Triggers", namespaces);
            if (containers == null || containers.Count != 1)
            {
                throw Invalid();
            }

            var triggers = new List<System.Xml.XmlElement>();
            foreach (System.Xml.XmlNode node in containers[0].ChildNodes)
            {
                System.Xml.XmlElement element = node as System.Xml.XmlElement;
                if (element != null)
                {
                    triggers.Add(element);
                }
            }
            if (triggers.Count != 1)
            {
                throw Invalid();
            }

            System.Xml.XmlElement trigger = triggers[0];
            if (!string.Equals(trigger.LocalName, "LogonTrigger", StringComparison.Ordinal) ||
                !string.Equals(trigger.NamespaceURI, TaskNamespace, StringComparison.Ordinal))
            {
                throw Invalid();
            }

            var children = new List<System.Xml.XmlElement>();
            foreach (System.Xml.XmlNode node in trigger.ChildNodes)
            {
                System.Xml.XmlElement element = node as System.Xml.XmlElement;
                if (element != null)
                {
                    children.Add(element);
                }
            }
            if (children.Count != 2 ||
                children.Count(delegate (System.Xml.XmlElement item)
                    {
                        return string.Equals(item.LocalName, "Enabled", StringComparison.Ordinal) &&
                            string.Equals(item.NamespaceURI, TaskNamespace, StringComparison.Ordinal);
                    }) != 1 ||
                children.Count(delegate (System.Xml.XmlElement item)
                    {
                        return string.Equals(item.LocalName, "UserId", StringComparison.Ordinal) &&
                            string.Equals(item.NamespaceURI, TaskNamespace, StringComparison.Ordinal);
                    }) != 1)
            {
                throw Invalid();
            }

            return new AgentTaskTriggerXmlSnapshot(trigger.LocalName, children.Count);
        }

        private static AcceptanceContractException Invalid()
        {
            return new AcceptanceContractException("acceptance_agent_task_invalid");
        }
    }

    public sealed class AgentTaskExecutionSnapshot
    {
        public AgentTaskExecutionSnapshot(
            string principalSid,
            string executablePath,
            string arguments,
            string logonType,
            string runLevel,
            string triggerKind,
            string source,
            string description,
            bool networkRequired,
            bool enabled,
            int triggerCount,
            int actionCount,
            string restartInterval = "PT1M",
            int restartCount = 3)
        {
            PrincipalSid = principalSid;
            ExecutablePath = executablePath;
            Arguments = arguments;
            LogonType = logonType;
            RunLevel = runLevel;
            TriggerKind = triggerKind;
            Source = source;
            Description = description;
            NetworkRequired = networkRequired;
            Enabled = enabled;
            TriggerCount = triggerCount;
            ActionCount = actionCount;
            RestartInterval = restartInterval;
            RestartCount = restartCount;
        }

        public string PrincipalSid { get; private set; }
        public string ExecutablePath { get; private set; }
        public string Arguments { get; private set; }
        public string LogonType { get; private set; }
        public string RunLevel { get; private set; }
        public string TriggerKind { get; private set; }
        public string Source { get; private set; }
        public string Description { get; private set; }
        public bool NetworkRequired { get; private set; }
        public bool Enabled { get; private set; }
        public int TriggerCount { get; private set; }
        public int ActionCount { get; private set; }
        public string RestartInterval { get; private set; }
        public int RestartCount { get; private set; }
    }

    public static class AgentTaskExecutionPolicy
    {
        public static void Validate(AgentTaskExecutionSnapshot expected, AgentTaskExecutionSnapshot actual)
        {
            if (expected == null ||
                actual == null ||
                !string.Equals(expected.PrincipalSid, actual.PrincipalSid, StringComparison.Ordinal) ||
                !string.Equals(expected.ExecutablePath, actual.ExecutablePath, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(expected.Arguments, actual.Arguments, StringComparison.Ordinal) ||
                !string.Equals(expected.LogonType, actual.LogonType, StringComparison.Ordinal) ||
                !string.Equals(expected.RunLevel, actual.RunLevel, StringComparison.Ordinal) ||
                !string.Equals(expected.TriggerKind, actual.TriggerKind, StringComparison.Ordinal) ||
                !string.Equals(expected.Source, actual.Source, StringComparison.Ordinal) ||
                !string.Equals(expected.Description, actual.Description, StringComparison.Ordinal) ||
                expected.NetworkRequired != actual.NetworkRequired ||
                expected.Enabled != actual.Enabled ||
                expected.TriggerCount != 1 ||
                actual.TriggerCount != 1 ||
                expected.ActionCount != 1 ||
                actual.ActionCount != 1 ||
                !string.Equals(expected.RestartInterval, "PT1M", StringComparison.Ordinal) ||
                !string.Equals(actual.RestartInterval, expected.RestartInterval, StringComparison.Ordinal) ||
                expected.RestartCount != 3 ||
                actual.RestartCount != expected.RestartCount)
            {
                throw new AcceptanceContractException("acceptance_agent_task_invalid");
            }
        }
    }

    public sealed class ChildProcessObservation
    {
        public ChildProcessObservation(
            int processId,
            string principalSid,
            int sessionId,
            string executablePath,
            string runId,
            bool commandLineMatches)
        {
            ProcessId = processId;
            PrincipalSid = principalSid;
            SessionId = sessionId;
            ExecutablePath = executablePath;
            RunId = runId;
            CommandLineMatches = commandLineMatches;
        }

        public int ProcessId { get; private set; }
        public string PrincipalSid { get; private set; }
        public int SessionId { get; private set; }
        public string ExecutablePath { get; private set; }
        public string RunId { get; private set; }
        public bool CommandLineMatches { get; private set; }
    }

    public static class ChildProcessObservationPolicy
    {
        public static void Validate(ChildProcessObservation expected, ChildProcessObservation actual)
        {
            if (expected == null ||
                actual == null ||
                expected.ProcessId <= 0 ||
                expected.ProcessId != actual.ProcessId ||
                !string.Equals(expected.PrincipalSid, actual.PrincipalSid, StringComparison.Ordinal) ||
                expected.SessionId <= 0 ||
                expected.SessionId != actual.SessionId ||
                !string.Equals(expected.ExecutablePath, actual.ExecutablePath, StringComparison.OrdinalIgnoreCase) ||
                !AcceptanceInputPolicy.IsRunId(expected.RunId) ||
                !string.Equals(expected.RunId, actual.RunId, StringComparison.Ordinal) ||
                !expected.CommandLineMatches ||
                !actual.CommandLineMatches)
            {
                throw new AcceptanceContractException("acceptance_child_process_invalid");
            }
        }
    }

    public sealed class SessionCandidate
    {
        public SessionCandidate(int sessionId, string state, string principalHash)
        {
            SessionId = sessionId;
            State = state;
            PrincipalHash = principalHash;
        }

        public int SessionId { get; private set; }

        public string State { get; private set; }

        public string PrincipalHash { get; private set; }
    }

    public static class SessionSelectionPolicy
    {
        public static int SelectUniqueActive(IEnumerable<SessionCandidate> candidates, string expectedPrincipalHash)
        {
            if (candidates == null || !AcceptanceInputPolicy.IsUpperHex(expectedPrincipalHash, 64))
            {
                throw new AcceptanceContractException("acceptance_session_unavailable");
            }

            int selected = 0;
            int count = 0;
            foreach (SessionCandidate candidate in candidates)
            {
                if (candidate != null &&
                    candidate.SessionId > 0 &&
                    string.Equals(candidate.State, "Active", StringComparison.Ordinal) &&
                    string.Equals(candidate.PrincipalHash, expectedPrincipalHash, StringComparison.Ordinal))
                {
                    selected = candidate.SessionId;
                    count++;
                }
            }

            if (count != 1)
            {
                throw new AcceptanceContractException("acceptance_session_unavailable");
            }

            return selected;
        }
    }

    public sealed class AcceptanceTaskSnapshot
    {
        public AcceptanceTaskSnapshot(
            string description,
            string principalHash,
            string logonType,
            string runLevel,
            string executableIdentity,
            string argumentsHash,
            int executionTimeLimitSeconds,
            int actionCount)
        {
            Description = description;
            PrincipalHash = principalHash;
            LogonType = logonType;
            RunLevel = runLevel;
            ExecutableIdentity = executableIdentity;
            ArgumentsHash = argumentsHash;
            ExecutionTimeLimitSeconds = executionTimeLimitSeconds;
            ActionCount = actionCount;
        }

        public string Description { get; private set; }

        public string PrincipalHash { get; private set; }

        public string LogonType { get; private set; }

        public string RunLevel { get; private set; }

        public string ExecutableIdentity { get; private set; }

        public string ArgumentsHash { get; private set; }

        public int ExecutionTimeLimitSeconds { get; private set; }

        public int ActionCount { get; private set; }
    }

    public static class TaskOwnershipPolicy
    {
        public static bool IsExact(AcceptanceTaskSnapshot expected, AcceptanceTaskSnapshot actual)
        {
            return expected != null &&
                actual != null &&
                string.Equals(expected.Description, actual.Description, StringComparison.Ordinal) &&
                string.Equals(expected.PrincipalHash, actual.PrincipalHash, StringComparison.Ordinal) &&
                string.Equals(expected.LogonType, actual.LogonType, StringComparison.Ordinal) &&
                string.Equals(expected.RunLevel, actual.RunLevel, StringComparison.Ordinal) &&
                string.Equals(expected.ExecutableIdentity, actual.ExecutableIdentity, StringComparison.Ordinal) &&
                string.Equals(expected.ArgumentsHash, actual.ArgumentsHash, StringComparison.Ordinal) &&
                expected.ExecutionTimeLimitSeconds == actual.ExecutionTimeLimitSeconds &&
                expected.ActionCount == 1 &&
                actual.ActionCount == 1;
        }
    }

    public static class ArtifactSetPolicy
    {
        public static void ValidateExact(IEnumerable<string> expected, IEnumerable<string> actual)
        {
            if (expected == null || actual == null)
            {
                throw new AcceptanceContractException("acceptance_artifact_set_invalid");
            }

            string[] expectedItems = expected.ToArray();
            string[] actualItems = actual.ToArray();
            var expectedSet = new HashSet<string>(expectedItems, StringComparer.Ordinal);
            var actualSet = new HashSet<string>(actualItems, StringComparer.Ordinal);
            if (expectedItems.Length == 0 ||
                expectedSet.Count != expectedItems.Length ||
                actualSet.Count != actualItems.Length ||
                !expectedSet.SetEquals(actualSet))
            {
                throw new AcceptanceContractException("acceptance_artifact_set_invalid");
            }
        }
    }

    public static class CleanupOwnershipPolicy
    {
        public static bool CanDelete(
            string expectedRunId,
            string markerRunId,
            string expectedIdentity,
            string actualIdentity,
            bool isReparse,
            bool isOrdinaryFile,
            int linkCount)
        {
            return AcceptanceInputPolicy.IsRunId(expectedRunId) &&
                string.Equals(expectedRunId, markerRunId, StringComparison.Ordinal) &&
                !string.IsNullOrEmpty(expectedIdentity) &&
                string.Equals(expectedIdentity, actualIdentity, StringComparison.Ordinal) &&
                !isReparse &&
                isOrdinaryFile &&
                linkCount == 1;
        }
    }

    public static class SecretScanPolicy
    {
        private const string RedactedTotpSecret = "[REDACTED_TOTP_SECRET]";

        private static readonly Regex OtpauthSecretPattern = new Regex(
            "(?<prefix>otpauth://[^\\s\\r\\n]*?(?:[?&]|&amp;)secret=)(?<secret>[^&\\s\\r\\n#\"'<>]+)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        private static readonly Regex Base32SecretPattern = new Regex(
            "^[A-Z2-7]+=*$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public static bool ContainsSensitive(string value)
        {
            return ContainsSensitive(value, string.Empty);
        }

        public static bool ContainsSensitive(string value, string base32Secret)
        {
            return !string.IsNullOrEmpty(value) &&
                !string.Equals(value, Redact(value, base32Secret), StringComparison.Ordinal);
        }

        public static string Redact(string value, string base32Secret)
        {
            if (value == null)
            {
                return string.Empty;
            }

            string redacted = OtpauthSecretPattern.Replace(value, match =>
                string.Equals(
                    match.Groups["secret"].Value,
                    RedactedTotpSecret,
                    StringComparison.Ordinal)
                    ? match.Value
                    : match.Groups["prefix"].Value + RedactedTotpSecret);
            if (!string.IsNullOrEmpty(base32Secret))
            {
                if (!Base32SecretPattern.IsMatch(base32Secret))
                {
                    throw new AcceptanceContractException("acceptance_otp_secret_invalid");
                }

                redacted = Regex.Replace(
                    redacted,
                    Regex.Escape(base32Secret),
                    RedactedTotpSecret,
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            }

            return redacted;
        }

        public static string ExtractTotpSecret(string otpauthUri)
        {
            MatchCollection matches = OtpauthSecretPattern.Matches(otpauthUri ?? string.Empty);
            if (matches.Count != 1)
            {
                throw new AcceptanceContractException("acceptance_otp_uri_invalid");
            }

            string secret = Uri.UnescapeDataString(matches[0].Groups["secret"].Value);
            if (secret.Length < 8 || secret.Length > 512 || !Base32SecretPattern.IsMatch(secret))
            {
                throw new AcceptanceContractException("acceptance_otp_uri_invalid");
            }

            return secret;
        }
    }

    public static class TrxArtifactPolicy
    {
        private static readonly Regex AssemblyPattern = new Regex(
            "^[A-Za-z0-9_.-]+\\.dll$",
            RegexOptions.CultureInvariant);

        public static string Sanitize(
            string rawXml,
            string expectedAssembly,
            string hostName,
            string userName)
        {
            return Sanitize(rawXml, expectedAssembly, hostName, userName, string.Empty);
        }

        public static string Sanitize(
            string rawXml,
            string expectedAssembly,
            string hostName,
            string userName,
            string totpSecret)
        {
            if (string.IsNullOrEmpty(rawXml) ||
                rawXml.Length > 16 * 1024 * 1024 ||
                !AssemblyPattern.IsMatch(expectedAssembly ?? string.Empty) ||
                string.IsNullOrWhiteSpace(hostName) ||
                string.IsNullOrWhiteSpace(userName))
            {
                throw new AcceptanceContractException("acceptance_trx_invalid");
            }

            var settings = new System.Xml.XmlReaderSettings();
            settings.DtdProcessing = System.Xml.DtdProcessing.Prohibit;
            settings.XmlResolver = null;
            var document = new System.Xml.XmlDocument();
            document.XmlResolver = null;
            try
            {
                string redactedXml = SecretScanPolicy.Redact(rawXml, totpSecret);
                using (var text = new System.IO.StringReader(redactedXml))
                using (var reader = System.Xml.XmlReader.Create(text, settings))
                {
                    document.Load(reader);
                }
            }
            catch (AcceptanceContractException)
            {
                throw;
            }
            catch (Exception)
            {
                throw new AcceptanceContractException("acceptance_trx_invalid");
            }

            System.Xml.XmlElement root = document.DocumentElement;
            if (root == null || !string.Equals(root.LocalName, "TestRun", StringComparison.Ordinal))
            {
                throw new AcceptanceContractException("acceptance_trx_invalid");
            }

            foreach (System.Xml.XmlNode node in document.SelectNodes("//*"))
            {
                System.Xml.XmlElement element = node as System.Xml.XmlElement;
                if (element == null)
                {
                    continue;
                }

                foreach (System.Xml.XmlAttribute attribute in element.Attributes)
                {
                    if (string.Equals(attribute.LocalName, "storage", StringComparison.Ordinal))
                    {
                        string fileName = System.IO.Path.GetFileName(
                            attribute.Value.Replace('\\', System.IO.Path.DirectorySeparatorChar));
                        if (!string.Equals(fileName, expectedAssembly, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new AcceptanceContractException("acceptance_trx_invalid");
                        }
                    }
                }
            }

            foreach (System.Xml.XmlNode node in document.SelectNodes("//@*|//text()"))
            {
                string value = node.Value ?? string.Empty;
                if (SecretScanPolicy.ContainsSensitive(value, totpSecret))
                {
                    throw new AcceptanceContractException("acceptance_sensitive_artifact");
                }
            }

            var output = new System.Text.StringBuilder(rawXml.Length);
            var writerSettings = new System.Xml.XmlWriterSettings();
            writerSettings.OmitXmlDeclaration = true;
            writerSettings.Indent = false;
            writerSettings.NewLineHandling = System.Xml.NewLineHandling.None;
            using (System.Xml.XmlWriter writer = System.Xml.XmlWriter.Create(output, writerSettings))
            {
                document.Save(writer);
            }
            string sanitized = output.ToString();
            if (SecretScanPolicy.ContainsSensitive(sanitized, totpSecret))
            {
                throw new AcceptanceContractException("acceptance_sensitive_artifact");
            }
            return sanitized;
        }
    }

    public sealed class WindowsFileIdentitySnapshot
    {
        public WindowsFileIdentitySnapshot(string identity, uint linkCount)
        {
            Identity = identity;
            LinkCount = linkCount;
        }

        public string Identity { get; private set; }

        public uint LinkCount { get; private set; }
    }

    public static class WindowsFileIdentity
    {
        private const uint GenericRead = 0x80000000;
        private const uint FileReadAttributes = 0x00000080;
        private const uint DeleteAccess = 0x00010000;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint ShareDelete = 0x00000004;
        private const uint OpenExisting = 3;
        private const uint OpenReparsePoint = 0x00200000;
        private const uint BackupSemantics = 0x02000000;
        private const uint SymbolicLinkFlagAllowUnprivilegedCreate = 0x2;
        private const uint DirectoryAttribute = 0x00000010;
        private const uint ReparsePointAttribute = 0x00000400;

        public static WindowsFileIdentitySnapshot Read(string path, bool directory)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new AcceptanceContractException("acceptance_file_identity_invalid");
            }

            uint flags = OpenReparsePoint | (directory ? BackupSemantics : 0U);
            using (SafeFileHandle handle = CreateFileW(
                path,
                GenericRead | FileReadAttributes,
                ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero,
                OpenExisting,
                flags,
                IntPtr.Zero))
            {
                ByHandleFileInformation information;
                if (handle.IsInvalid || !GetFileInformationByHandle(handle, out information))
                {
                    throw new AcceptanceContractException("acceptance_file_identity_invalid");
                }

                string identity = information.VolumeSerialNumber.ToString("X8") + ":" +
                    information.FileIndexHigh.ToString("X8") + ":" +
                    information.FileIndexLow.ToString("X8");
                return new WindowsFileIdentitySnapshot(identity, information.NumberOfLinks);
            }
        }

        public static void CreateHardLink(string linkPath, string targetPath)
        {
            if (!CreateHardLinkW(linkPath, targetPath, IntPtr.Zero))
            {
                throw new AcceptanceContractException("acceptance_fixture_hardlink_failed");
            }
        }

        public static void CreateFileSymbolicLink(string linkPath, string targetPath)
        {
            if (!CreateSymbolicLinkW(linkPath, targetPath, SymbolicLinkFlagAllowUnprivilegedCreate) &&
                !CreateSymbolicLinkW(linkPath, targetPath, 0))
            {
                throw new AcceptanceContractException("acceptance_fixture_reparse_failed");
            }
        }

        public static bool DeleteOrdinaryFileIfExact(
            string path,
            string expectedIdentity,
            string expectedSha256)
        {
            if (string.IsNullOrEmpty(path) ||
                string.IsNullOrEmpty(expectedIdentity) ||
                !AcceptanceInputPolicy.IsLowerHex(expectedSha256, 64))
            {
                return false;
            }

            try
            {
                return DeleteOrdinaryFileIfExactCore(path, expectedIdentity, expectedSha256);
            }
            catch
            {
                return false;
            }
        }

        public static bool DeleteOrdinaryFileIfExactWithRetry(
            string path,
            string expectedIdentity,
            string expectedSha256,
            int timeoutMilliseconds,
            int delayMilliseconds)
        {
            if (timeoutMilliseconds < 1 || timeoutMilliseconds > 30000)
            {
                throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            }
            if (delayMilliseconds < 1 || delayMilliseconds > timeoutMilliseconds)
            {
                throw new ArgumentOutOfRangeException("delayMilliseconds");
            }

            Win32Exception lastFailure = null;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            do
            {
                try
                {
                    return DeleteOrdinaryFileIfExactCore(path, expectedIdentity, expectedSha256);
                }
                catch (Win32Exception failure)
                {
                    lastFailure = failure;
                }

                if (stopwatch.ElapsedMilliseconds >= timeoutMilliseconds)
                {
                    break;
                }
                System.Threading.Thread.Sleep(delayMilliseconds);
            }
            while (true);

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(lastFailure).Throw();
            return false;
        }

        private static bool DeleteOrdinaryFileIfExactCore(
            string path,
            string expectedIdentity,
            string expectedSha256)
        {
            if (string.IsNullOrEmpty(path) ||
                string.IsNullOrEmpty(expectedIdentity) ||
                !AcceptanceInputPolicy.IsLowerHex(expectedSha256, 64))
            {
                return false;
            }

            using (SafeFileHandle handle = CreateFileW(
                    path,
                    GenericRead | FileReadAttributes | DeleteAccess,
                    ShareRead | ShareWrite,
                    IntPtr.Zero,
                    OpenExisting,
                    OpenReparsePoint,
                    IntPtr.Zero))
            {
                if (handle.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                ByHandleFileInformation information;
                if (!GetFileInformationByHandle(handle, out information))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                if ((information.FileAttributes & (DirectoryAttribute | ReparsePointAttribute)) != 0 ||
                    information.NumberOfLinks != 1)
                {
                    return false;
                }

                string actualIdentity = information.VolumeSerialNumber.ToString("X8") + ":" +
                    information.FileIndexHigh.ToString("X8") + ":" +
                    information.FileIndexLow.ToString("X8");
                if (!string.Equals(actualIdentity, expectedIdentity, StringComparison.Ordinal))
                {
                    return false;
                }

                string actualSha256;
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] buffer = new byte[81920];
                    try
                    {
                        while (true)
                        {
                            uint read;
                            if (!ReadFile(handle, buffer, (uint)buffer.Length, out read, IntPtr.Zero))
                            {
                                throw new Win32Exception(Marshal.GetLastWin32Error());
                            }
                            if (read == 0)
                            {
                                break;
                            }
                            sha256.TransformBlock(buffer, 0, (int)read, buffer, 0);
                        }
                        sha256.TransformFinalBlock(new byte[0], 0, 0);
                        byte[] completedHash = sha256.Hash ?? new byte[0];
                        if (completedHash.Length != 32)
                        {
                            return false;
                        }
                        actualSha256 = BitConverter.ToString(completedHash)
                            .Replace("-", string.Empty)
                            .ToLowerInvariant();
                    }
                    finally
                    {
                        Array.Clear(buffer, 0, buffer.Length);
                    }
                }
                if (!FixedTimeEquals(actualSha256, expectedSha256))
                {
                    return false;
                }

                var disposition = new FileDispositionInformation { DeleteFile = true };
                if (!SetFileInformationByHandle(
                        handle,
                        4,
                        ref disposition,
                        (uint)Marshal.SizeOf(typeof(FileDispositionInformation))))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return true;
            }
        }

        private static bool FixedTimeEquals(string left, string right)
        {
            int difference = left.Length ^ right.Length;
            int count = Math.Min(left.Length, right.Length);
            for (int index = 0; index < count; index++)
            {
                difference |= left[index] ^ right[index];
            }
            return difference == 0;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileTime
        {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public FileTime CreationTime;
            public FileTime LastAccessTime;
            public FileTime LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileDispositionInformation
        {
            [MarshalAs(UnmanagedType.Bool)]
            public bool DeleteFile;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation information);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile(
            SafeFileHandle file,
            byte[] buffer,
            uint bytesToRead,
            out uint bytesRead,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int fileInformationClass,
            ref FileDispositionInformation fileInformation,
            uint bufferSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateHardLinkW(
            string fileName,
            string existingFileName,
            IntPtr securityAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateSymbolicLinkW(
            string symbolicFileName,
            string targetFileName,
            uint flags);
    }

    public static class AuthenticodeSignatureSequence
    {
        private const int TrustENoSignature = unchecked((int)0x800B0100);
        private const uint GetSecondarySignatureCount = 0x00000002;
        private const uint VerifySpecificSignature = 0x00000001;
        private const uint MaximumSecondarySignatures = 63;

        public static string[] ReadSuffixes(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
            }

            SignatureProbe primary = Probe(path, 0, GetSecondarySignatureCount);
            if (primary.Status == TrustENoSignature)
            {
                return new string[0];
            }

            EnsureSuccessful(primary);
            if (primary.SecondarySignatureCount > MaximumSecondarySignatures)
            {
                throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
            }

            List<string> suffixes = new List<string>();
            suffixes.Add(ToSuffix(primary.Thumbprint));
            for (uint index = 1; index <= primary.SecondarySignatureCount; index++)
            {
                SignatureProbe secondary = Probe(path, index, VerifySpecificSignature);
                EnsureSuccessful(secondary);
                suffixes.Add(ToSuffix(secondary.Thumbprint));
            }

            return suffixes.ToArray();
        }

        private static string ToSuffix(string thumbprint)
        {
            string normalized = thumbprint == null
                ? string.Empty
                : thumbprint.Replace(" ", string.Empty).ToUpperInvariant();
            if (!AcceptanceInputPolicy.IsUpperHex(normalized, 40))
            {
                throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
            }

            return normalized.Substring(32, 8);
        }

        private static void EnsureSuccessful(SignatureProbe probe)
        {
            if (probe.Status != 0 || string.IsNullOrEmpty(probe.Thumbprint))
            {
                throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
            }
        }

        private static SignatureProbe Probe(string path, uint signatureIndex, uint signatureFlags)
        {
            WinTrustFileInfo fileInfo = new WinTrustFileInfo(path);
            WinTrustSignatureSettings settings = new WinTrustSignatureSettings(signatureIndex, signatureFlags);
            IntPtr fileInfoPointer = IntPtr.Zero;
            IntPtr settingsPointer = IntPtr.Zero;
            bool fileInfoInitialized = false;
            bool settingsInitialized = false;
            WinTrustData trustData = new WinTrustData();
            Guid action = NativeMethods.GenericVerifyV2;
            try
            {
                fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFileInfo)));
                Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
                fileInfoInitialized = true;
                settingsPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustSignatureSettings)));
                Marshal.StructureToPtr(settings, settingsPointer, false);
                settingsInitialized = true;
                trustData = new WinTrustData(fileInfoPointer, settingsPointer);

                int status = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
                if (status != 0)
                {
                    return new SignatureProbe(status, 0, string.Empty);
                }

                if (trustData.StateData == IntPtr.Zero)
                {
                    throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
                }

                WinTrustSignatureSettings updatedSettings =
                    (WinTrustSignatureSettings)Marshal.PtrToStructure(
                        settingsPointer,
                        typeof(WinTrustSignatureSettings));
                IntPtr providerData = NativeMethods.WTHelperProvDataFromStateData(trustData.StateData);
                IntPtr signer = providerData == IntPtr.Zero
                    ? IntPtr.Zero
                    : NativeMethods.WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
                IntPtr providerCertificatePointer = signer == IntPtr.Zero
                    ? IntPtr.Zero
                    : NativeMethods.WTHelperGetProvCertFromChain(signer, 0);
                if (providerCertificatePointer == IntPtr.Zero)
                {
                    throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
                }

                CryptProviderCertificate providerCertificate =
                    (CryptProviderCertificate)Marshal.PtrToStructure(
                        providerCertificatePointer,
                        typeof(CryptProviderCertificate));
                if (providerCertificate.CertificateContext == IntPtr.Zero)
                {
                    throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
                }

                using (X509Certificate2 certificate =
                    new X509Certificate2(providerCertificate.CertificateContext))
                {
                    return new SignatureProbe(
                        status,
                        updatedSettings.SecondarySignatureCount,
                        certificate.Thumbprint ?? string.Empty);
                }
            }
            catch (AcceptanceContractException)
            {
                throw;
            }
            catch (Exception)
            {
                throw new AcceptanceContractException("acceptance_signer_sequence_invalid");
            }
            finally
            {
                if (trustData.StateData != IntPtr.Zero)
                {
                    try
                    {
                        trustData.StateAction = WinTrustData.StateActionClose;
                        NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
                    }
                    catch
                    {
                    }
                }

                FreeMarshaled(settingsPointer, typeof(WinTrustSignatureSettings), settingsInitialized);
                FreeMarshaled(fileInfoPointer, typeof(WinTrustFileInfo), fileInfoInitialized);
            }
        }

        private static void FreeMarshaled(IntPtr pointer, Type type, bool initialized)
        {
            if (pointer == IntPtr.Zero)
            {
                return;
            }

            if (initialized)
            {
                try
                {
                    Marshal.DestroyStructure(pointer, type);
                }
                catch
                {
                }
            }

            Marshal.FreeHGlobal(pointer);
        }

        private sealed class SignatureProbe
        {
            public SignatureProbe(int status, uint secondarySignatureCount, string thumbprint)
            {
                Status = status;
                SecondarySignatureCount = secondarySignatureCount;
                Thumbprint = thumbprint;
            }

            public int Status { get; private set; }
            public uint SecondarySignatureCount { get; private set; }
            public string Thumbprint { get; private set; }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustFileInfo
        {
            public WinTrustFileInfo(string path)
            {
                Size = (uint)Marshal.SizeOf(typeof(WinTrustFileInfo));
                FilePath = path;
                FileHandle = IntPtr.Zero;
                KnownSubject = IntPtr.Zero;
            }

            public uint Size;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string FilePath;
            public IntPtr FileHandle;
            public IntPtr KnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WinTrustSignatureSettings
        {
            public WinTrustSignatureSettings(uint signatureIndex, uint flags)
            {
                Size = (uint)Marshal.SizeOf(typeof(WinTrustSignatureSettings));
                SignatureIndex = signatureIndex;
                Flags = flags;
                SecondarySignatureCount = 0;
                VerifiedSignatureIndex = 0;
                CryptoPolicy = IntPtr.Zero;
            }

            public uint Size;
            public uint SignatureIndex;
            public uint Flags;
            public uint SecondarySignatureCount;
            public uint VerifiedSignatureIndex;
            public IntPtr CryptoPolicy;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WinTrustData
        {
            public const uint StateActionVerify = 0x00000001;
            public const uint StateActionClose = 0x00000002;
            private const uint ProviderFlagRevocationCheckNone = 0x00000010;

            public WinTrustData(IntPtr fileInfo, IntPtr settings)
            {
                Size = (uint)Marshal.SizeOf(typeof(WinTrustData));
                PolicyCallbackData = IntPtr.Zero;
                SipClientData = IntPtr.Zero;
                UiChoice = 2;
                RevocationChecks = 0;
                UnionChoice = 1;
                FileInfo = fileInfo;
                StateAction = StateActionVerify;
                StateData = IntPtr.Zero;
                UrlReference = IntPtr.Zero;
                ProviderFlags = ProviderFlagRevocationCheckNone;
                UiContext = 0;
                SignatureSettings = settings;
            }

            public uint Size;
            public IntPtr PolicyCallbackData;
            public IntPtr SipClientData;
            public uint UiChoice;
            public uint RevocationChecks;
            public uint UnionChoice;
            public IntPtr FileInfo;
            public uint StateAction;
            public IntPtr StateData;
            public IntPtr UrlReference;
            public uint ProviderFlags;
            public uint UiContext;
            public IntPtr SignatureSettings;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CryptProviderCertificate
        {
            public uint Size;
            public IntPtr CertificateContext;
        }

        private static class NativeMethods
        {
            public static Guid GenericVerifyV2
            {
                get { return new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE"); }
            }

            [DllImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
            public static extern int WinVerifyTrust(
                IntPtr windowHandle,
                ref Guid actionId,
                ref WinTrustData trustData);

            [DllImport("wintrust.dll", EntryPoint = "WTHelperProvDataFromStateData")]
            public static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

            [DllImport("wintrust.dll", EntryPoint = "WTHelperGetProvSignerFromChain")]
            public static extern IntPtr WTHelperGetProvSignerFromChain(
                IntPtr providerData,
                uint signerIndex,
                [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
                uint counterSignerIndex);

            [DllImport("wintrust.dll", EntryPoint = "WTHelperGetProvCertFromChain")]
            public static extern IntPtr WTHelperGetProvCertFromChain(
                IntPtr providerSigner,
                uint certificateIndex);
        }
    }

    public static class PinnedHttpClientFactory
    {
        private static readonly Regex TokenPattern = new Regex(
            "^[A-Za-z0-9_-]{43}$",
            RegexOptions.CultureInvariant);

        public static HttpClient Create(string certificateSha256, string bearerToken)
        {
            bool useCertificatePin = !string.IsNullOrEmpty(certificateSha256);
            if ((useCertificatePin && !AcceptanceInputPolicy.IsUpperHex(certificateSha256, 64)) ||
                bearerToken == null ||
                !TokenPattern.IsMatch(bearerToken))
            {
                throw new AcceptanceContractException("acceptance_http_configuration_invalid");
            }

            var handler = new HttpClientHandler();
            handler.AllowAutoRedirect = false;
            handler.UseCookies = false;
            if (useCertificatePin)
            {
                handler.ServerCertificateCustomValidationCallback = delegate (
                    HttpRequestMessage request,
                    System.Security.Cryptography.X509Certificates.X509Certificate2 certificate,
                    System.Security.Cryptography.X509Certificates.X509Chain chain,
                    System.Net.Security.SslPolicyErrors errors)
                {
                    if (certificate == null)
                    {
                        return false;
                    }

                    byte[] actual;
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        actual = sha256.ComputeHash(certificate.RawData);
                    }
                    string actualHex = BitConverter.ToString(actual).Replace("-", string.Empty);
                    int difference = actualHex.Length ^ certificateSha256.Length;
                    int count = Math.Min(actualHex.Length, certificateSha256.Length);
                    for (int index = 0; index < count; index++)
                    {
                        difference |= actualHex[index] ^ certificateSha256[index];
                    }

                    return difference == 0;
                };
            }
            var client = new HttpClient(handler, true);
            client.Timeout = System.Threading.Timeout.InfiniteTimeSpan;
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", bearerToken);
            return client;
        }
    }

    public static class AcceptanceLsaSecret
    {
        private const uint PolicyAccess = 0x00000004 | 0x00000020;
        private const uint StatusObjectNameNotFound = 0xC0000034;
        private static readonly Regex KeyPattern = new Regex(
            "^CodeSignAuto/Acceptance/[0-9a-f]{32}/Api$",
            RegexOptions.CultureInvariant);

        public static void StoreNew(string key, string secret)
        {
            if (!ValidKey(key) || !ValidSecret(secret) || Retrieve(key) != null)
            {
                throw Invalid();
            }

            IntPtr policy = OpenPolicy();
            try
            {
                using (UnicodeBuffer keyBuffer = new UnicodeBuffer(key))
                using (UnicodeBuffer secretBuffer = new UnicodeBuffer(secret))
                {
                    ThrowStatus(NativeMethods.LsaStorePrivateData(
                        policy,
                        ref keyBuffer.Value,
                        ref secretBuffer.Value));
                }
            }
            finally
            {
                NativeMethods.LsaClose(policy);
            }

            string readback = null;
            try
            {
                readback = Retrieve(key);
                if (!FixedEquals(secret, readback))
                {
                    try { Remove(key); } catch { }
                    throw Invalid();
                }
            }
            finally
            {
                readback = null;
            }
        }

        public static string Retrieve(string key)
        {
            if (!ValidKey(key))
            {
                throw Invalid();
            }

            IntPtr policy = OpenPolicy();
            IntPtr privateData = IntPtr.Zero;
            try
            {
                using (UnicodeBuffer keyBuffer = new UnicodeBuffer(key))
                {
                    uint status = NativeMethods.LsaRetrievePrivateData(
                        policy,
                        ref keyBuffer.Value,
                        out privateData);
                    if (status == StatusObjectNameNotFound || NativeMethods.LsaNtStatusToWinError(status) == 2)
                    {
                        return null;
                    }
                    ThrowStatus(status);
                }

                LsaUnicodeString value = (LsaUnicodeString)Marshal.PtrToStructure(
                    privateData,
                    typeof(LsaUnicodeString));
                if (value.Buffer == IntPtr.Zero ||
                    value.Length < 2 ||
                    value.Length > 8192 ||
                    value.MaximumLength < value.Length ||
                    value.MaximumLength > 8194 ||
                    value.Length % 2 != 0 ||
                    value.MaximumLength % 2 != 0)
                {
                    throw Invalid();
                }

                int charCount = value.Length / 2;
                char[] characters = new char[charCount];
                try
                {
                    Marshal.Copy(value.Buffer, characters, 0, charCount);
                    return new string(characters);
                }
                finally
                {
                    for (int index = 0; index < value.Length; index++)
                    {
                        Marshal.WriteByte(value.Buffer, index, 0);
                    }
                    Array.Clear(characters, 0, characters.Length);
                }
            }
            finally
            {
                if (privateData != IntPtr.Zero)
                {
                    NativeMethods.LsaFreeMemory(privateData);
                }
                NativeMethods.LsaClose(policy);
            }
        }

        public static void Remove(string key)
        {
            if (!ValidKey(key))
            {
                throw Invalid();
            }

            IntPtr policy = OpenPolicy();
            try
            {
                using (UnicodeBuffer keyBuffer = new UnicodeBuffer(key))
                {
                    ThrowStatus(NativeMethods.LsaStorePrivateDataNull(
                        policy,
                        ref keyBuffer.Value,
                        IntPtr.Zero));
                }
            }
            finally
            {
                NativeMethods.LsaClose(policy);
            }

            if (Retrieve(key) != null)
            {
                throw Invalid();
            }
        }

        private static IntPtr OpenPolicy()
        {
            LsaObjectAttributes attributes = new LsaObjectAttributes();
            attributes.Length = Marshal.SizeOf(typeof(LsaObjectAttributes));
            IntPtr policy;
            ThrowStatus(NativeMethods.LsaOpenPolicy(
                IntPtr.Zero,
                ref attributes,
                PolicyAccess,
                out policy));
            return policy;
        }

        private static bool ValidKey(string key)
        {
            return key != null && KeyPattern.IsMatch(key);
        }

        private static bool ValidSecret(string secret)
        {
            return !string.IsNullOrWhiteSpace(secret) &&
                secret.Length <= 4096 &&
                secret.IndexOfAny(new[] { '\r', '\n', '\0' }) < 0;
        }

        private static bool FixedEquals(string left, string right)
        {
            if (left == null || right == null)
            {
                return false;
            }
            int difference = left.Length ^ right.Length;
            int length = Math.Min(left.Length, right.Length);
            for (int index = 0; index < length; index++)
            {
                difference |= left[index] ^ right[index];
            }
            return difference == 0;
        }

        private static void ThrowStatus(uint status)
        {
            if (status != 0)
            {
                throw Invalid();
            }
        }

        private static AcceptanceContractException Invalid()
        {
            return new AcceptanceContractException("acceptance_lsa_secret_invalid");
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaObjectAttributes
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LsaUnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        private sealed class UnicodeBuffer : IDisposable
        {
            private IntPtr _buffer;
            private readonly int _bytes;

            public UnicodeBuffer(string value)
            {
                char[] characters = value.ToCharArray();
                _bytes = checked((characters.Length + 1) * 2);
                _buffer = Marshal.AllocHGlobal(_bytes);
                try
                {
                    Marshal.Copy(characters, 0, _buffer, characters.Length);
                    Marshal.WriteInt16(_buffer, characters.Length * 2, 0);
                    Value = new LsaUnicodeString
                    {
                        Length = checked((ushort)(characters.Length * 2)),
                        MaximumLength = checked((ushort)_bytes),
                        Buffer = _buffer
                    };
                }
                finally
                {
                    Array.Clear(characters, 0, characters.Length);
                }
            }

            public LsaUnicodeString Value;

            public void Dispose()
            {
                if (_buffer == IntPtr.Zero)
                {
                    return;
                }
                for (int index = 0; index < _bytes; index++)
                {
                    Marshal.WriteByte(_buffer, index, 0);
                }
                Marshal.FreeHGlobal(_buffer);
                _buffer = IntPtr.Zero;
                Value = new LsaUnicodeString();
            }
        }

        private static class NativeMethods
        {
            [DllImport("advapi32.dll")]
            public static extern uint LsaOpenPolicy(
                IntPtr systemName,
                ref LsaObjectAttributes objectAttributes,
                uint desiredAccess,
                out IntPtr policyHandle);

            [DllImport("advapi32.dll")]
            public static extern uint LsaStorePrivateData(
                IntPtr policyHandle,
                ref LsaUnicodeString keyName,
                ref LsaUnicodeString privateData);

            [DllImport("advapi32.dll", EntryPoint = "LsaStorePrivateData")]
            public static extern uint LsaStorePrivateDataNull(
                IntPtr policyHandle,
                ref LsaUnicodeString keyName,
                IntPtr privateData);

            [DllImport("advapi32.dll")]
            public static extern uint LsaRetrievePrivateData(
                IntPtr policyHandle,
                ref LsaUnicodeString keyName,
                out IntPtr privateData);

            [DllImport("advapi32.dll")]
            public static extern uint LsaNtStatusToWinError(uint status);

            [DllImport("advapi32.dll")]
            public static extern uint LsaFreeMemory(IntPtr buffer);

            [DllImport("advapi32.dll")]
            public static extern uint LsaClose(IntPtr handle);
        }
    }
}
