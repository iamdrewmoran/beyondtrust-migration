<#
.SYNOPSIS
    Export BeyondTrust Password Safe managed account metadata and, optionally, plaintext passwords to CSV.

.DESCRIPTION
    Authenticates to the BeyondTrust BeyondInsight/Password Safe v3 REST API using a registered application key,
    enumerates managed accounts for the specified managed system, and writes deterministic CSV output. When the
    IncludePassword switch is supplied, the script performs a compliant credential checkout/retrieval/check-in
    sequence per account and records plaintext passwords only after interactive confirmation (or when -Force is
    explicitly specified).

.PARAMETER BaseUrl
    The BeyondTrust BeyondInsight/Password Safe public API base URL (e.g. https://host/BeyondTrust/api/public/v3).

.PARAMETER ApiKey
    The BeyondTrust API key. Provide via parameter, environment variable, or Windows Credential Manager. The
    Authorization header is derived from this value. If omitted, ApiKeyEnvironmentVariable and ApiKeyCredentialName
    are consulted.

.PARAMETER ApiKeyEnvironmentVariable
    Name of the environment variable that stores the API key. Defaults to BT_API_KEY.

.PARAMETER ApiKeyCredentialName
    Target name in Windows Credential Manager storing the API key as the credential password. Optional.

.PARAMETER SystemName
    Managed system name filter. Specify SystemName or SystemId (or both).

.PARAMETER SystemId
    Managed system numeric identifier filter.

.PARAMETER AccountName
    Optional managed account name filter.

.PARAMETER OutputPath
    Destination CSV file path. CSV is emitted as UTF-8 with BOM.

.PARAMETER IncludePassword
    When supplied, plaintext passwords are exported after performing compliant checkout/retrieve/check-in requests.

.PARAMETER Reason
    Justification recorded with checkout requests. Required when IncludePassword is supplied.

.PARAMETER ReleaseDurationMinutes
    Optional checkout duration override in minutes. Defaults to policy if omitted.

.PARAMETER Force
    Bypass interactive confirmation when exporting plaintext passwords (use sparingly and only when policy permits).

.PARAMETER PassThru
    Emit the exported objects to the pipeline in addition to writing the CSV.

.PARAMETER WhatIf
    Displays what would happen during password export (e.g. checkout/check-in) without executing the changes.

.PARAMETER Verbose
    Provides detailed operational logging with secrets automatically masked.

.EXAMPLE
    .\Export-BTAccounts.ps1 -BaseUrl "https://bi.example.com/BeyondTrust/api/public/v3" -SystemName "AD-DC01" `
        -OutputPath ".\accounts.csv"

.EXAMPLE
    .\Export-BTAccounts.ps1 -BaseUrl "https://bi.example.com/BeyondTrust/api/public/v3" -SystemName "LINUX-FARM" `
        -OutputPath ".\secrets.csv" -IncludePassword -Reason "Break-glass restore"
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BaseUrl,

    [Parameter()]
    [string]$ApiKey,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ApiKeyEnvironmentVariable = 'BT_API_KEY',

    [Parameter()]
    [string]$ApiKeyCredentialName,

    [Parameter()]
    [string]$SystemName,

    [Parameter()]
    [Nullable[int]]$SystemId,

    [Parameter()]
    [string]$AccountName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$IncludePassword,

    [Parameter()]
    [string]$Reason,

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$ReleaseDurationMinutes,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:BaseApiUrl = $null
$script:SessionHeaders = @{}
$script:SessionInfo = [ordered]@{}
$script:ExitCode = 0

$script:CredentialTypeLoaded = $false

function Get-WindowsCredentialSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName
    )

    if (-not $IsWindows) {
        return $null
    }

    if (-not $script:CredentialTypeLoaded) {
        $typeDefinition = @'
using System;
using System.Runtime.InteropServices;

namespace BT.Credential
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public enum CredentialType : uint
    {
        Generic = 1,
    }

    public static class CredMan
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CredReadW")]
        public static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern void CredFree(IntPtr buffer);
    }
}
'@

        Add-Type -TypeDefinition $typeDefinition -ErrorAction Stop
        $script:CredentialTypeLoaded = $true
    }

    $credentialPtr = [IntPtr]::Zero
    $readSuccess = [BT.Credential.CredMan]::CredRead($TargetName, [BT.Credential.CredentialType]::Generic, 0, [ref]$credentialPtr)
    if (-not $readSuccess -or $credentialPtr -eq [IntPtr]::Zero) {
        return $null
    }

    try {
        $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credentialPtr, [type][BT.Credential.CREDENTIAL])
        if ($credential.CredentialBlobSize -gt 0 -and $credential.CredentialBlob -ne [IntPtr]::Zero) {
            $buffer = New-Object byte[] $credential.CredentialBlobSize
            [System.Runtime.InteropServices.Marshal]::Copy($credential.CredentialBlob, $buffer, 0, $credential.CredentialBlobSize)
            $secret = [System.Text.Encoding]::Unicode.GetString($buffer)
            return $secret.TrimEnd([char]0)
        }
    }
    finally {
        [BT.Credential.CredMan]::CredFree($credentialPtr)
    }

    return $null
}

function Get-BTApiKey {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ExplicitApiKey,

        [Parameter(Mandatory = $true)]
        [string]$EnvironmentVariableName,

        [Parameter()]
        [string]$CredentialTargetName
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitApiKey)) {
        return $ExplicitApiKey
    }

    if (-not [string]::IsNullOrWhiteSpace($EnvironmentVariableName)) {
        $candidate = [Environment]::GetEnvironmentVariable($EnvironmentVariableName)
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            return $candidate
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($CredentialTargetName)) {
        try {
            $credentialValue = $null
            if (Get-Module -ListAvailable -Name CredentialManager) {
                Import-Module CredentialManager -ErrorAction Stop | Out-Null
                $cred = Get-StoredCredential -Target $CredentialTargetName -ErrorAction Stop
                if ($null -ne $cred) {
                    $credentialValue = $cred.Password
                }
            }
            else {
                $credentialValue = Get-WindowsCredentialSecret -TargetName $CredentialTargetName
            }

            if (-not [string]::IsNullOrWhiteSpace($credentialValue)) {
                return $credentialValue
            }
        }
        catch {
            Write-Warning "Failed to retrieve credential '$CredentialTargetName' from Windows Credential Manager: $_"
        }
    }

    throw "Unable to determine API key. Provide -ApiKey, set the $EnvironmentVariableName environment variable, or store the key in Credential Manager."
}

function ConvertTo-QueryString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $pairs = @()
    foreach ($kvp in $Parameters.GetEnumerator() | Where-Object { $null -ne $_.Value -and $_.Value -ne '' }) {
        $encodedKey = [System.Net.WebUtility]::UrlEncode($kvp.Key)
        $encodedValue = [System.Net.WebUtility]::UrlEncode([string]$kvp.Value)
        $pairs += "$encodedKey=$encodedValue"
    }

    if ($pairs.Count -gt 0) {
        return '?' + ($pairs -join '&')
    }

    return [string]::Empty
}

function Join-RelativeUri {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Base,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [hashtable]$Query
    )

    $cleanBase = $Base.TrimEnd('/')
    $cleanPath = $Path.TrimStart('/')
    $uri = "$cleanBase/$cleanPath"
    if ($null -ne $Query -and $Query.Keys.Count -gt 0) {
        $uri += ConvertTo-QueryString -Parameters $Query
    }

    return $uri
}

function Invoke-BTApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [hashtable]$Headers,

        [Parameter()]
        [hashtable]$Query,

        [Parameter()]
        [int]$TimeoutSec = 120,

        [Parameter()]
        [int]$MaxRetries = 5,

        [Parameter()]
        [int]$InitialDelaySeconds = 2,

        [Parameter()]
        [switch]$SkipSessionHeaders
    )

    if (-not $script:BaseApiUrl) {
        throw 'API base URL is not initialized.'
    }

    $attempt = 0
    $lastError = $null

    $contentType = 'application/json; charset=utf-8'

    do {
        $attempt++
        $effectiveHeaders = @{}
        if (-not $SkipSessionHeaders -and $script:SessionHeaders) {
            foreach ($kvp in $script:SessionHeaders.GetEnumerator()) {
                $effectiveHeaders[$kvp.Key] = $kvp.Value
            }
        }

        if ($Headers) {
            foreach ($kvp in $Headers.GetEnumerator()) {
                $effectiveHeaders[$kvp.Key] = $kvp.Value
            }
        }

        if (-not $effectiveHeaders.ContainsKey('Accept')) {
            $effectiveHeaders['Accept'] = 'application/json'
        }

        $uri = Join-RelativeUri -Base $script:BaseApiUrl -Path $Path -Query $Query

        $bodyToSend = $null
        if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
            if ($Body -is [string]) {
                $bodyToSend = $Body
            }
            else {
                $bodyToSend = $Body | ConvertTo-Json -Depth 10
            }
            if (-not $effectiveHeaders.ContainsKey('Content-Type')) {
                $effectiveHeaders['Content-Type'] = $contentType
            }
        }

        $secretPropertyNames = @('Password', 'Secret', 'ApiKey', 'AccessKey')
        $safeBody = if ($Body -and ($Body.PSObject.Properties.Name | Where-Object { $secretPropertyNames -contains $_ })) {
            $clone = $Body | ConvertTo-Json -Depth 10 | ConvertFrom-Json
            foreach ($propName in $secretPropertyNames) {
                if ($clone.PSObject.Properties.Name -contains $propName) {
                    $clone.$propName = '***'
                }
            }
            $clone | ConvertTo-Json -Depth 10
        }
        elseif ($Body) {
            $Body | ConvertTo-Json -Depth 4
        }
        else {
            $null
        }

        Write-Verbose ("[{0}] {1} {2} {3}" -f (Get-Date).ToString('s'), $Method, $uri, $(if ($safeBody) { "Body=$safeBody" } else { '' }))

        try {
            $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $effectiveHeaders -Body $bodyToSend -TimeoutSec $TimeoutSec -ErrorAction Stop
            return $response
        }
        catch [Microsoft.PowerShell.Commands.HttpResponseException], [System.Net.WebException] {
            $lastError = $_
            $statusCode = $null
            $retryable = $false
            $responseBody = $null

            if ($_.Exception.Response -and $_.Exception.Response -is [System.Net.HttpWebResponse]) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                try {
                    $responseBody = $reader.ReadToEnd()
                }
                finally {
                    $reader.Dispose()
                }

                if ($statusCode -eq 429 -or $statusCode -ge 500) {
                    $retryable = $true
                }
            }
            elseif ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::Timeout) {
                $retryable = $true
            }

            $errorMessage = "API request failed (attempt $attempt/$MaxRetries) - Method: $Method Uri: $uri StatusCode: $statusCode Response: $responseBody"
            if ($retryable -and $attempt -lt $MaxRetries) {
                $delay = [Math]::Pow(2, $attempt - 1) * $InitialDelaySeconds
                Write-Warning "$errorMessage. Retrying in $delay second(s)."
                Start-Sleep -Seconds $delay
                continue
            }

            throw $errorMessage
        }
    }
    while ($attempt -lt $MaxRetries)

    if ($lastError) {
        throw $lastError
    }
}

function Initialize-BTSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ApiKeyValue
    )

    $script:SessionHeaders = @{
        Authorization = "PS-Auth $ApiKeyValue"
    }

    $signInBody = [ordered]@{
        ApiKey = $ApiKeyValue
    }

    $response = Invoke-BTApi -Method 'POST' -Path 'Auth/SignAppIn' -Body $signInBody

    if ($null -eq $response) {
        throw 'Auth/SignAppIn returned no data.'
    }

    $script:SessionInfo = [ordered]@{}
    foreach ($prop in $response.PSObject.Properties) {
        $script:SessionInfo[$prop.Name] = $prop.Value
    }

    $tokenValue = $null
    foreach ($propertyName in @('AuthToken', 'Token', 'BearerToken', 'SessionToken')) {
        if ($response.PSObject.Properties.Name -contains $propertyName) {
            $tokenValue = $response.$propertyName
            break
        }
    }

    if ($tokenValue) {
        $script:SessionHeaders['Authorization'] = "PS-Auth $ApiKeyValue:$tokenValue"
        $script:SessionHeaders['X-Auth-Token'] = $tokenValue
    }

    if ($response.PSObject.Properties.Name -contains 'AppKey') {
        $script:SessionHeaders['X-App-Key'] = $response.AppKey
    }

    Write-Verbose 'Authentication succeeded.'
    return $response
}

function Invoke-BTSignOut {
    [CmdletBinding()]
    param()

    try {
        if ($script:SessionHeaders.Count -eq 0) {
            return
        }

        $body = [ordered]@{}
        foreach ($tokenProperty in @('AuthToken', 'Token', 'BearerToken')) {
            if ($script:SessionInfo.Contains($tokenProperty)) {
                $body[$tokenProperty] = $script:SessionInfo[$tokenProperty]
            }
        }

        if ($body.Keys.Count -eq 0) {
            $body = $null
        }

        Invoke-BTApi -Method 'POST' -Path 'Auth/SignOut' -Body $body | Out-Null
        Write-Verbose 'Signed out of BeyondTrust session.'
    }
    catch {
        Write-Warning "Sign out failed: $_"
    }
    finally {
        $script:SessionHeaders.Clear()
    }
}

function Get-PropertyValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]$PropertyNames
    )

    foreach ($name in $PropertyNames) {
        if ($InputObject.PSObject.Properties.Name -contains $name) {
            return $InputObject.$name
        }
    }

    return $null
}

function Get-BTManagedAccounts {
    [CmdletBinding()]
    param(
        [Parameter()]
        [Nullable[int]]$SystemId,

        [Parameter()]
        [string]$SystemName,

        [Parameter()]
        [string]$AccountName
    )

    $pageSize = 100
    $pageNumber = 1
    $results = @()
    $totalCount = $null
    $hasMore = $true

    while ($hasMore) {
        $query = @{
            PageSize   = $pageSize
            PageNumber = $pageNumber
        }

        if ($SystemId) {
            $query['SystemId'] = $SystemId
        }

        if ($SystemName) {
            $query['SystemName'] = $SystemName
        }

        if ($AccountName) {
            $query['AccountName'] = $AccountName
        }

        # Include alternative pagination keys for backward compatibility
        $query['Limit'] = $pageSize
        $query['Offset'] = ($pageNumber - 1) * $pageSize

        $response = Invoke-BTApi -Method 'GET' -Path 'ManagedAccounts' -Query $query
        if ($null -eq $response) {
            break
        }

        $items = $null
        if ($response.PSObject.Properties.Name -contains 'Results') {
            $items = $response.Results
        }
        elseif ($response.PSObject.Properties.Name -contains 'Accounts') {
            $items = $response.Accounts
        }
        elseif ($response.PSObject.Properties.Name -contains 'Records') {
            $items = $response.Records
        }
        elseif ($response -is [System.Collections.IEnumerable] -and -not ($response -is [string])) {
            $items = $response
        }
        else {
            $items = @($response)
        }

        if ($items) {
            $results += $items
        }

        $itemCount = if ($items -is [System.Collections.ICollection]) { $items.Count } elseif ($items) { ($items | Measure-Object).Count } else { 0 }

        if ($response.PSObject.Properties.Name -contains 'TotalCount') {
            $totalCount = $response.TotalCount
        }
        elseif ($response.PSObject.Properties.Name -contains 'Count') {
            $totalCount = $response.Count
        }
        elseif ($results) {
            $totalCount = $results.Count
        }

        if ($response.PSObject.Properties.Name -contains 'HasMore') {
            $hasMore = [bool]$response.HasMore
        }
        elseif ($response.PSObject.Properties.Name -contains 'MoreAvailable') {
            $hasMore = [bool]$response.MoreAvailable
        }
        elseif ($totalCount) {
            $hasMore = ($results.Count -lt $totalCount)
        }
        else {
            $hasMore = ($itemCount -ge $pageSize)
        }

        $pageNumber++
    }

    return $results
}

function Checkin-BTRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$RequestId,

        [Parameter()]
        [string]$Reason
    )

    $body = $null
    if ($Reason) {
        $body = @{ Reason = $Reason }
    }

    Invoke-BTApi -Method 'PUT' -Path ("Requests/{0}/Checkin" -f $RequestId) -Body $body | Out-Null
}

function Request-BTCredentials {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ManagedAccount,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [Parameter()]
        [Nullable[int]]$DurationMinutes
    )

    $managedAccountId = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('ManagedAccountId', 'AccountId', 'Id')
    if (-not $managedAccountId) {
        throw 'Unable to resolve managed account identifier for checkout request.'
    }

    $requestBody = [ordered]@{
        ManagedAccountId = $managedAccountId
        AccessType       = 'View'
        Reason           = $Reason
    }

    if ($DurationMinutes) {
        $requestBody['DurationMinutes'] = $DurationMinutes
    }

    $systemName = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('SystemName', 'SystemDisplayName')
    $accountName = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('AccountName', 'Name')
    if (-not $systemName) {
        $systemName = "SystemId:$($ManagedAccount.SystemId)"
    }
    if (-not $accountName) {
        $accountName = "AccountId:$managedAccountId"
    }

    if (-not $PSCmdlet.ShouldProcess("$systemName/$accountName", 'Request credential checkout')) {
        return $null
    }

    $requestResponse = Invoke-BTApi -Method 'POST' -Path 'Requests' -Body $requestBody
    $requestId = $null
    foreach ($candidate in @('RequestId', 'Id')) {
        if ($requestResponse.PSObject.Properties.Name -contains $candidate) {
            $requestId = $requestResponse.$candidate
            break
        }
    }

    if (-not $requestId) {
        throw 'Credential request did not return a request identifier.'
    }

    $credentialResponse = $null
    try {
        $credentialResponse = Invoke-BTApi -Method 'GET' -Path ("Credentials/{0}" -f $requestId)
        return [pscustomobject]@{
            RequestId = $requestId
            Credential = $credentialResponse
        }
    }
    finally {
        try {
            if ($requestId) {
                $checkInReason = 'Automated export checkout'
                Checkin-BTRequest -RequestId $requestId -Reason $checkInReason
            }
        }
        catch {
            Write-Warning "Failed to check in request $requestId: $_"
        }
    }
}

function Get-CsvHeaders {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$IncludePassword
    )

    $headers = @('SystemName', 'AccountName', 'DomainName', 'LastChangeDate', 'NextChangeDate', 'ApiEnabled')
    if ($IncludePassword) {
        $headers += 'Password'
    }

    return $headers
}

function Write-CsvRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ManagedAccount,

        [Parameter()]
        [string]$Password,

        [Parameter()]
        [switch]$IncludePassword
    )

    $props = [ordered]@{}
    $props['SystemName'] = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('SystemName', 'SystemDisplayName')
    $props['AccountName'] = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('AccountName', 'Name')
    $props['DomainName'] = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('DomainName', 'Domain')
    $props['LastChangeDate'] = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('LastChangeDate', 'LastChange', 'PasswordLastChangedDate')
    $props['NextChangeDate'] = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('NextChangeDate', 'PasswordNextChange', 'NextRotationDate')
    $props['ApiEnabled'] = Get-PropertyValue -InputObject $ManagedAccount -PropertyNames @('ApiEnabled', 'IsApiEnabled')

    if ($IncludePassword) {
        $props['Password'] = $Password
    }

    return [pscustomobject]$props
}

function Ensure-Directory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $directory = Split-Path -Path $Path -Parent
    if (-not $directory) {
        return
    }

    if (-not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

function Write-EmptyCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [switch]$IncludePassword
    )

    Ensure-Directory -Path $Path
    $headers = Get-CsvHeaders -IncludePassword:$IncludePassword
    $encoding = New-Object System.Text.UTF8Encoding($true)
    $content = ($headers -join ',') + [Environment]::NewLine
    [System.IO.File]::WriteAllText($Path, $content, $encoding)
}

try {
    if (-not $SystemName -and -not $SystemId) {
        throw 'Provide either -SystemName or -SystemId to identify the target managed system.'
    }

    if ($IncludePassword -and -not $Force) {
        $caption = 'Plaintext password export confirmation'
        $message = 'Plaintext passwords will be exported to disk. Confirm that policy requirements are satisfied.'
        if (-not $PSCmdlet.ShouldContinue($message, $caption)) {
            Write-Warning 'Export cancelled by user.'
            return
        }
    }

    if ($IncludePassword -and -not $Reason) {
        throw 'The -Reason parameter is required when IncludePassword is specified.'
    }

    if ($IncludePassword) {
        Write-Warning 'Plaintext passwords will be written to the output CSV. Protect the file and purge it when complete.'
    }

    $script:BaseApiUrl = $BaseUrl.TrimEnd('/')

    $apiKeyValue = Get-BTApiKey -ExplicitApiKey $ApiKey -EnvironmentVariableName $ApiKeyEnvironmentVariable -CredentialTargetName $ApiKeyCredentialName

    Initialize-BTSession -ApiKeyValue $apiKeyValue | Out-Null

    $accounts = Get-BTManagedAccounts -SystemId $SystemId -SystemName $SystemName -AccountName $AccountName

    if (-not $accounts -or $accounts.Count -eq 0) {
        Write-Warning 'No managed accounts found with the supplied filters.'
        Write-EmptyCsv -Path $OutputPath -IncludePassword:$IncludePassword.IsPresent
        return
    }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($account in $accounts) {
        $passwordValue = $null
        if ($IncludePassword) {
            $requestResult = Request-BTCredentials -ManagedAccount $account -Reason $Reason -DurationMinutes $ReleaseDurationMinutes
            if ($null -ne $requestResult -and $requestResult.Credential) {
                $passwordValue = Get-PropertyValue -InputObject $requestResult.Credential -PropertyNames @('Password', 'Secret', 'CredentialText')
            }
        }

        $row = Write-CsvRow -ManagedAccount $account -IncludePassword:$IncludePassword.IsPresent -Password $passwordValue
        $rows.Add($row) | Out-Null
    }

    Ensure-Directory -Path $OutputPath
    $rows | Export-Csv -Path $OutputPath -Encoding utf8BOM -NoTypeInformation
    Write-Verbose ("Exported {0} account(s) to {1}" -f $rows.Count, $OutputPath)

    if ($PassThru) {
        $rows
    }
}
catch {
    $script:ExitCode = 1
    $errorMessage = if ($_.Exception) { $_.Exception.Message } else { $_.ToString() }
    Write-Error -Message $errorMessage
    Write-Verbose ("Detailed error: {0}" -f ($_.ToString()))
}
finally {
    try {
        Invoke-BTSignOut
    }
    catch {
        Write-Warning "Final sign-out attempt failed: $_"
    }

    if ($MyInvocation.MyCommand.Path) {
        exit $script:ExitCode
    }
    else {
        $global:LASTEXITCODE = $script:ExitCode
    }
}
