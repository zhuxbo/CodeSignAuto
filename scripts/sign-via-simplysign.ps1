Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http

function Move-SimplySignArtifactIntoPlace {
    param(
        [Parameter(Mandatory = $true)][string]$SignedPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    if ($null -eq ('SimplySignAuto.Release.RemoteSigningNativeMethods' -as [type])) {
        Add-Type -Namespace SimplySignAuto.Release -Name RemoteSigningNativeMethods -MemberDefinition @'
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);
'@
    }
    $replaceExistingAndWriteThrough = 0x00000009
    if (-not [SimplySignAuto.Release.RemoteSigningNativeMethods]::MoveFileEx(
            $SignedPath,
            $DestinationPath,
            $replaceExistingAndWriteThrough)) {
        throw 'release_signing_replace_failed'
    }
}

function ConvertTo-CanonicalCertificateSerial {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value -cnotmatch '^[0-9A-Fa-f]+$' -or $Value -cnotmatch '[0-9]') {
        throw 'release_signing_parameters_invalid'
    }

    $canonical = if (($Value.Length % 2) -eq 0) { $Value } else { '0' + $Value }
    while ($canonical.Length -gt 2 -and $canonical.StartsWith('00', [StringComparison]::Ordinal)) {
        $canonical = $canonical.Substring(2)
    }

    return $canonical.ToUpperInvariant()
}

function Read-SigningJson {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string[]]$AllowedProperties,
        [Parameter(Mandatory = $true)][string[]]$RequiredProperties
    )

    try {
        $value = ConvertFrom-Json -InputObject $Content -ErrorAction Stop
    }
    catch {
        throw 'release_signing_response_invalid'
    }

    if ($null -eq $value -or $value -is [Array] -or $value -is [string]) {
        throw 'release_signing_response_invalid'
    }

    $names = @($value.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($name in $names) {
        if ($AllowedProperties -cnotcontains $name) {
            throw 'release_signing_response_invalid'
        }
    }
    foreach ($name in $RequiredProperties) {
        if ($names -cnotcontains $name) {
            throw 'release_signing_response_invalid'
        }
    }

    return $value
}

function Invoke-SimplySignArtifact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$InputPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$BearerToken,
        [Parameter(Mandatory = $true)][string]$CertificateSerialNumber,
        [Parameter(Mandatory = $true)][string]$IdempotencyPrefix,
        [Parameter(Mandatory = $true)][TimeSpan]$Timeout
    )

    $inputFullPath = [IO.Path]::GetFullPath($InputPath)
    $outputFullPath = [IO.Path]::GetFullPath($OutputPath)
    $partPath = Join-Path `
        ([IO.Path]::GetDirectoryName($outputFullPath)) `
        ([IO.Path]::GetFileNameWithoutExtension($outputFullPath) + '.part' +
            [IO.Path]::GetExtension($outputFullPath))
    if (-not [IO.File]::Exists($inputFullPath) -or
        [string]::Equals($inputFullPath, $outputFullPath, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.File]::Exists($outputFullPath) -or
        [IO.File]::Exists($partPath) -or
        -not [IO.Directory]::Exists([IO.Path]::GetDirectoryName($outputFullPath)) -or
        [string]::IsNullOrWhiteSpace($BearerToken) -or
        $BearerToken.IndexOfAny([char[]]@("`r", "`n", [char]0)) -ge 0 -or
        $IdempotencyPrefix -cnotmatch '^[!-~]{1,48}$' -or
        $Timeout -le [TimeSpan]::Zero) {
        throw 'release_signing_parameters_invalid'
    }

    $baseUri = $null
    if (-not [Uri]::TryCreate($BaseUrl, [UriKind]::Absolute, [ref]$baseUri) -or
        ($baseUri.Scheme -cne 'http' -and $baseUri.Scheme -cne 'https') -or
        -not [string]::IsNullOrEmpty($baseUri.UserInfo) -or
        -not [string]::IsNullOrEmpty($baseUri.Query) -or
        -not [string]::IsNullOrEmpty($baseUri.Fragment)) {
        throw 'release_signing_parameters_invalid'
    }

    $serial = ConvertTo-CanonicalCertificateSerial -Value $CertificateSerialNumber
    $inputHash = (Get-FileHash -LiteralPath $inputFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $idempotencyKey = "$IdempotencyPrefix-$inputHash"
    if ($idempotencyKey.Length -gt 128) {
        throw 'release_signing_parameters_invalid'
    }

    $rootUri = [Uri]::new($baseUri.AbsoluteUri.TrimEnd('/') + '/')
    $jobsUri = [Uri]::new($rootUri, 'v1/jobs')
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseDefaultCredentials = $false
    $handler.PreAuthenticate = $false
    $handler.UseCookies = $false
    $handler.Credentials = $null
    $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler, $true)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $client.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $BearerToken)
    $timeoutCancellation = [Threading.CancellationTokenSource]::new($Timeout)
    $partCreated = $false
    try {
        $fileStream = [IO.File]::Open(
            $inputFullPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        try {
            $multipart = [System.Net.Http.MultipartFormDataContent]::new(
                'ssa-release-' + [Guid]::NewGuid().ToString('N'))
            try {
                $parametersJson =
                    '{"kind":"authenticode","certificateSerialNumber":"' +
                    $serial +
                    '","digestAlgorithm":"sha256","appendSignature":false}'
                $parameters = [System.Net.Http.StringContent]::new(
                    $parametersJson,
                    [Text.Encoding]::UTF8,
                    'application/json')
                $multipart.Add($parameters, 'parameters')
                $file = [System.Net.Http.StreamContent]::new($fileStream)
                $file.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new(
                    'application/octet-stream')
                $multipart.Add($file, 'file', [IO.Path]::GetFileName($inputFullPath))
                $request = [System.Net.Http.HttpRequestMessage]::new(
                    [System.Net.Http.HttpMethod]::Post,
                    $jobsUri)
                try {
                    $request.Headers.TryAddWithoutValidation('Idempotency-Key', $idempotencyKey) | Out-Null
                    $request.Content = $multipart
                    $response = $client.SendAsync(
                        $request,
                        [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                        $timeoutCancellation.Token).GetAwaiter().GetResult()
                    try {
                        if ($response.StatusCode -ne [System.Net.HttpStatusCode]::Accepted) {
                            throw "release_signing_http_failed_$([int]$response.StatusCode)"
                        }
                        $createdJson = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    }
                    finally {
                        $response.Dispose()
                    }
                }
                finally {
                    $request.Dispose()
                }
            }
            finally {
                $multipart.Dispose()
            }
        }
        finally {
            $fileStream.Dispose()
        }

        $created = Read-SigningJson `
            -Content $createdJson `
            -AllowedProperties @('jobId', 'state', 'statusUrl', 'resultUrl', 'expiresAt') `
            -RequiredProperties @('jobId', 'state', 'statusUrl', 'resultUrl', 'expiresAt')
        $jobId = [Guid]::Empty
        if (-not [Guid]::TryParseExact([string]$created.jobId, 'D', [ref]$jobId)) {
            throw 'release_signing_response_invalid'
        }
        $statusPath = "/v1/jobs/$($jobId.ToString('D'))"
        $resultPath = "$statusPath/result"
        if ([string]$created.statusUrl -cne $statusPath -or
            [string]$created.resultUrl -cne $resultPath -or
            [string]$created.state -cnotin @(
                'queued', 'waiting_for_agent', 'signing', 'verifying', 'succeeded')) {
            throw 'release_signing_response_invalid'
        }

        $resultSha256 = $null
        while ($true) {
            $statusResponse = $client.GetAsync(
                [Uri]::new($rootUri, $statusPath.TrimStart('/')),
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                $timeoutCancellation.Token).GetAwaiter().GetResult()
            try {
                if ($statusResponse.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                    throw "release_signing_http_failed_$([int]$statusResponse.StatusCode)"
                }
                $statusJson = $statusResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            }
            finally {
                $statusResponse.Dispose()
            }

            $status = Read-SigningJson `
                -Content $statusJson `
                -AllowedProperties @(
                    'jobId', 'state', 'originalName', 'inputSha256', 'resultSha256',
                    'errorCode', 'errorMessage', 'createdAt', 'startedAt', 'completedAt', 'expiresAt') `
                -RequiredProperties @('jobId', 'state')
            if ([string]$status.jobId -cne $jobId.ToString('D')) {
                throw 'release_signing_response_invalid'
            }
            $state = [string]$status.state
            if ($state -ceq 'succeeded') {
                $resultSha256 = [string]$status.resultSha256
                if ($resultSha256 -cnotmatch '^[0-9a-f]{64}$') {
                    throw 'release_signing_response_invalid'
                }
                break
            }
            if ($state -ceq 'failed' -or $state -ceq 'expired') {
                throw 'release_signing_job_failed'
            }
            if ($state -cnotin @('queued', 'waiting_for_agent', 'signing', 'verifying')) {
                throw 'release_signing_response_invalid'
            }
            [Threading.Tasks.Task]::Delay(
                [TimeSpan]::FromMilliseconds(500),
                $timeoutCancellation.Token).GetAwaiter().GetResult()
        }

        $resultResponse = $client.GetAsync(
            [Uri]::new($rootUri, $resultPath.TrimStart('/')),
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $timeoutCancellation.Token).GetAwaiter().GetResult()
        try {
            if ($resultResponse.StatusCode -ne [System.Net.HttpStatusCode]::OK) {
                throw "release_signing_http_failed_$([int]$resultResponse.StatusCode)"
            }
            $part = [IO.File]::Open(
                $partPath,
                [IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            $partCreated = $true
            try {
                $resultStream = $resultResponse.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                try {
                    $resultStream.CopyToAsync(
                        $part,
                        81920,
                        $timeoutCancellation.Token).GetAwaiter().GetResult()
                    $part.Flush($true)
                }
                finally {
                    $resultStream.Dispose()
                }
            }
            finally {
                $part.Dispose()
            }
        }
        finally {
            $resultResponse.Dispose()
        }

        if ((Get-FileHash -LiteralPath $partPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $resultSha256) {
            throw 'release_signing_result_invalid'
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $partPath
        if ($signature.Status -ne 'Valid' -or
            $null -eq $signature.SignerCertificate -or
            (ConvertTo-CanonicalCertificateSerial -Value $signature.SignerCertificate.SerialNumber) -cne
                $serial) {
            throw 'release_signing_identity_invalid'
        }

        [IO.File]::Move($partPath, $outputFullPath)
        $partCreated = $false
        return [IO.FileInfo]::new($outputFullPath)
    }
    catch [OperationCanceledException] {
        throw 'release_signing_timeout'
    }
    catch {
        if ($_.Exception.Message.StartsWith('release_signing_', [StringComparison]::Ordinal)) {
            throw
        }
        throw 'release_signing_failed'
    }
    finally {
        if ($partCreated -and [IO.File]::Exists($partPath)) {
            [IO.File]::Delete($partPath)
        }
        $timeoutCancellation.Dispose()
        $client.Dispose()
    }
}
