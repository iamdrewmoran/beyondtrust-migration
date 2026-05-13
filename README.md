# Export-BTAccounts

A PowerShell script that exports managed account metadata from **BeyondTrust BeyondInsight / Password Safe** to CSV via the v3 REST API. Supports optional plaintext password export through a fully compliant checkout → retrieve → check-in sequence, with interactive confirmation, `-WhatIf` support, and automatic secrets masking in verbose logs.

---

## Features

- **Authenticated API sessions** — signs in via `Auth/SignAppIn` and always signs out in a `finally` block, even on error
- **Three credential retrieval methods** — explicit parameter, environment variable, or Windows Credential Manager (no hardcoded secrets)
- **Automatic pagination** — retrieves all matching accounts regardless of result set size
- **Retry logic with exponential backoff** — handles transient `429` and `5xx` errors gracefully (up to 5 retries)
- **Compliant password export** — performs checkout → credential retrieval → check-in per account; requires `-Reason` and explicit confirmation (or `-Force` for automation)
- **`-WhatIf` support** — preview credential checkout operations without executing them
- **Secrets-safe verbose logging** — API keys and passwords are masked (`***`) in all log output
- **UTF-8 with BOM CSV output** — compatible with Excel without encoding issues

---

## Prerequisites

- **PowerShell 5.1+** (Windows) or **PowerShell 7+** (cross-platform, though Windows Credential Manager integration requires Windows)
- Access to a BeyondTrust BeyondInsight / Password Safe environment with a registered application API key
- The API key's associated application must have **read access** to Managed Accounts (and **checkout access** if using `-IncludePassword`)

---

## Credential Configuration

The script resolves the API key using the first method that returns a value:

**1. Explicit parameter (least preferred — avoid in automation)**
```powershell
.\Export-BTAccounts.ps1 -ApiKey "your-api-key" ...
```

**2. Environment variable (recommended for local use)**

Set the variable before running the script:
```powershell
$env:BT_API_KEY = "your-api-key"
```
Or use a different variable name via `-ApiKeyEnvironmentVariable`.

**3. Windows Credential Manager (recommended for scheduled tasks)**

Store the key as a Generic credential, then pass the target name:
```powershell
.\Export-BTAccounts.ps1 -ApiKeyCredentialName "BeyondTrust-API" ...
```
The script will read it securely at runtime without exposing it in command history.

---

## Usage

### Export account metadata only

```powershell
.\Export-BTAccounts.ps1 `
    -BaseUrl "https://bi.example.com/BeyondTrust/api/public/v3" `
    -SystemName "AD-DC01" `
    -OutputPath ".\accounts.csv"
```

### Export with plaintext passwords (requires confirmation)

```powershell
.\Export-BTAccounts.ps1 `
    -BaseUrl "https://bi.example.com/BeyondTrust/api/public/v3" `
    -SystemName "LINUX-FARM" `
    -OutputPath ".\secrets.csv" `
    -IncludePassword `
    -Reason "Break-glass restore"
```

### Preview password checkout operations without executing them

```powershell
.\Export-BTAccounts.ps1 `
    -BaseUrl "https://bi.example.com/BeyondTrust/api/public/v3" `
    -SystemName "AD-DC01" `
    -OutputPath ".\secrets.csv" `
    -IncludePassword `
    -Reason "Audit review" `
    -WhatIf
```

### Filter to a specific account and pass results to the pipeline

```powershell
.\Export-BTAccounts.ps1 `
    -BaseUrl "https://bi.example.com/BeyondTrust/api/public/v3" `
    -SystemName "AD-DC01" `
    -AccountName "svc-deploy" `
    -OutputPath ".\account.csv" `
    -PassThru | Select-Object AccountName, LastChangeDate
```

---

## Parameters

| Parameter | Required | Description |
|---|---|---|
| `-BaseUrl` | Yes | BeyondTrust API base URL (e.g. `https://host/BeyondTrust/api/public/v3`) |
| `-OutputPath` | Yes | Destination CSV file path |
| `-SystemName` | One of these | Managed system name filter |
| `-SystemId` | One of these | Managed system numeric ID filter |
| `-ApiKey` | No | Explicit API key (see Credential Configuration) |
| `-ApiKeyEnvironmentVariable` | No | Environment variable name storing the API key (default: `BT_API_KEY`) |
| `-ApiKeyCredentialName` | No | Windows Credential Manager target name |
| `-AccountName` | No | Optional account name filter |
| `-IncludePassword` | No | Export plaintext passwords via compliant checkout sequence |
| `-Reason` | No* | Justification recorded with checkout requests (*required with `-IncludePassword`) |
| `-ReleaseDurationMinutes` | No | Checkout duration override in minutes (1–1440; defaults to policy) |
| `-Force` | No | Skip interactive confirmation when exporting passwords |
| `-PassThru` | No | Emit exported objects to the pipeline in addition to writing CSV |
| `-WhatIf` | No | Preview checkout operations without executing them |
| `-Verbose` | No | Detailed operational logging with secrets masked |

---

## CSV Output

| Column | Description |
|---|---|
| `SystemName` | Managed system display name |
| `AccountName` | Managed account name |
| `DomainName` | Domain associated with the account |
| `LastChangeDate` | Date the password was last rotated |
| `NextChangeDate` | Scheduled date of next password rotation |
| `ApiEnabled` | Whether API access is enabled for the account |
| `Password` | Plaintext password *(only present when `-IncludePassword` is used)* |

---

## Security Notes

- **Never commit API keys.** Use an environment variable or Windows Credential Manager, and add any local `.env`-style files to `.gitignore`.
- **Protect CSV output.** Files produced with `-IncludePassword` contain plaintext credentials. Store them with appropriate access controls and purge them after use.
- **Scope API key permissions.** The application key should have the minimum permissions required — read-only access to Managed Accounts unless password export is needed.
- **Use `-Force` sparingly.** It bypasses the interactive confirmation prompt and is intended only for automation pipelines where policy requirements have been validated upstream.

---

## Author

**Drew Moran** — IAM Engineer  
[github.com/iamdrewmoran](https://github.com/iamdrewmoran)
