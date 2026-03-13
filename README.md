# Get-MailRecords

[![PSGallery Version](https://img.shields.io/powershellgallery/v/Get-MailRecords)](https://www.powershellgallery.com/packages/Get-MailRecords)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/Get-MailRecords)](https://www.powershellgallery.com/packages/Get-MailRecords)

Performs DNS lookups for mail-related records on a given domain, email address, or URL.
Checks **A, MX, NS, SPF, DMARC, and DKIM** records. Supports bulk/pipeline input and CSV/JSON export.

**Function alias:** `GMR` &nbsp;|&nbsp; **Repo:** https://github.com/dcazman/Get-MailRecords

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Parameters](#parameters)
- [Examples](#examples)
- [Output](#output)
- [GitHub Actions](#github-actions)
- [Notes](#notes)

---

## Requirements

| Environment   | Requirement |
| :------------ | :---------- |
| Windows       | PowerShell 5.1+ — uses built-in `Resolve-DnsName` |
| Linux / macOS | PowerShell 7+ with `dig` installed (`bind-utils` on RHEL/CentOS, `dnsutils` on Debian/Ubuntu) |

## Installation

Copy `Get-MailRecords.psm1` to a folder in your `$PSModulePath`, then import it:

```powershell
Import-Module Get-MailRecords
```

Or dot-source it directly for one-off use:

```powershell
. .\Get-MailRecords.psm1
```

## Parameters

| Parameter        | Alias   | Type     | Description |
| :--------------- | :------ | :------- | :---------- |
| `-Domain`        | `-d`    | String   | Full domain name, email address, or URL. **Mandatory.** Accepts pipeline input. |
| `-Sub`           | `-s`    | Switch   | Query the subdomain **and** the base domain. `mail.facebook.com` returns results for both `mail.facebook.com` and `facebook.com`. |
| `-JustSub`       | `-js`   | Switch   | Query only the subdomain — skips the base domain. `mail.facebook.com` returns results for `mail.facebook.com` only. |
| `-Selector`      | `-sel`  | String   | Explicit DKIM selector to query. If omitted, selectors in `-DkimSelectors` are tried automatically. |
| `-DkimSelectors` | `-dkim` | String[] | List of DKIM selectors to try when no `-Selector` is given. Defaults to a built-in common set. Pass your own to override or extend. |
| `-RecordType`    | `-r`    | String   | Record type to query for SPF, DMARC, and DKIM. Valid: `TXT` (default), `CNAME`, `BOTH`. |
| `-Server`        | `-srv`  | String   | DNS server to query. Default: `8.8.8.8`. |
| `-Export`        | `-e`    | String   | Export results to file. Provide a filename (`results.csv`, `output.json`) or just the format (`CSV`, `JSON`) for an auto-generated timestamped filename. |

## Examples

#### Basic lookup

```powershell
Get-MailRecords -Domain facebook.com
GMR -d facebook.com
```

#### Query subdomain and base domain together

```powershell
Get-MailRecords -Domain mail.facebook.com -Sub
GMR -d mail.facebook.com -s
```

#### Query only the subdomain

```powershell
Get-MailRecords -Domain mail.facebook.com -JustSub
GMR -d mail.facebook.com -js
```

#### Provide a DKIM selector explicitly

```powershell
Get-MailRecords -Domain facebook.com -Selector selector1
GMR -d facebook.com -sel selector1
```

#### Override the DKIM selector auto-discovery list

```powershell
Get-MailRecords -Domain example.com -DkimSelectors @('acmecorp', 'mail2024')
GMR -d example.com -dkim @('acmecorp', 'mail2024')
```

#### Query CNAME records for SPF / DMARC / DKIM

```powershell
Get-MailRecords -Domain facebook.com -RecordType CNAME
GMR -d facebook.com -r CNAME
```

#### Query both TXT and CNAME record types

```powershell
Get-MailRecords -Domain facebook.com -RecordType BOTH
GMR -d facebook.com -r BOTH
```

#### Use a custom DNS server

```powershell
Get-MailRecords -Domain cnn.com -Server 1.1.1.1
GMR -d cnn.com -srv 1.1.1.1
```

#### Export to a specific CSV file

```powershell
Get-MailRecords -Domain example.com -Export results.csv
GMR -d example.com -e results.csv
```

#### Export with an auto-generated timestamped filename

```powershell
Get-MailRecords -Domain example.com -Export JSON
GMR -d example.com -e JSON
# Saves as: MailRecords_20240101_1430.json
```

#### Pipeline — check multiple domains

```powershell
"google.com", "microsoft.com", "amazon.com" | Get-MailRecords -Export output.json
```

#### Pipeline — bulk check from a CSV file

```powershell
# CSV must have a column named 'Domain'
Import-Csv domains.csv | Get-MailRecords -Export results.csv
```

## Output

Results are returned as `PSCustomObject` with the following properties:

| Property              | Description |
| :-------------------- | :---------- |
| `A`                   | `True` if an A record exists, `False` otherwise |
| `MX`                  | MX records (Name, Preference, TTL) |
| `SPF_TXT` / `SPF_CNAME`   | SPF record value, or `False` if not found |
| `DMARC_TXT` / `DMARC_CNAME` | DMARC record value, or `False` if not found |
| `DKIM_TXT` / `DKIM_CNAME`  | DKIM record value, or `False` if not found |
| `SELECTOR`            | The DKIM selector that matched, or the selector provided |
| `DOMAIN`              | The domain that was queried |
| `RECORDTYPE`          | The record type queried (`TXT` or `CNAME`) |
| `SERVER`              | The DNS server used |
| `NS_First2`           | First two NS records |

---

## GitHub Actions

The included workflow (`get-mailrecords.yml`) lets you run `GMR` directly from GitHub without a local PowerShell environment. Results are published as an HTML report to **GitHub Pages** at:

```
https://<your-username>.github.io/<your-repo>/
```

Each run overwrites the previous report. The URL is permanent — there is no expiry.

### Setup (one-time)

1. Place `get-mailrecords.yml` in `.github/workflows/` in your repo.
2. Ensure `Get-MailRecords.psm1` is in the root of the repo.
3. Enable GitHub Pages: **Settings → Pages → Source → GitHub Actions**.

### Triggering a run

1. Go to **Actions → Get-MailRecords DNS Lookup**.
2. Click **Run workflow**.
3. Fill in the inputs and click **Run workflow** again.
4. When the run completes, the Pages URL will be live with the new report.

### Inputs

| Input | Required | Default | Description |
| :---- | :------- | :------ | :---------- |
| `domain` | Yes | — | Domain, email, or URL to query (e.g. `example.com`) |
| `selector` | No | *(auto-discover)* | DKIM selector. Leave blank to try the built-in selector list automatically. |
| `server` | No | `8.8.8.8` | DNS server to query. |
| `record_type` | No | `TXT` | Record type for SPF, DMARC, and DKIM. Options: `TXT`, `CNAME`, `BOTH`. |
| `sub` | No | `false` | ☑ Query the subdomain **and** the base domain. e.g. `mail.example.com` returns results for both. |
| `just_sub` | No | `false` | ☑ Query the subdomain **only** — skips the base domain lookup. |
| `export` | No | `false` | ☑ Export results to a timestamped CSV, downloadable from the run summary as an artifact (kept 30 days). |

### Limitations

- **One domain per run** — pipeline and bulk CSV input are not supported in the workflow. Run the module locally for bulk lookups.
- **Last run only** — the Pages report always reflects the most recent run. There is no history of previous results.
- **Windows runner required** — the workflow uses `windows-latest` for `Resolve-DnsName`. This is handled automatically; no configuration needed.
- **`sub` and `just_sub` are mutually exclusive** — checking both will pass both flags to the module; `-JustSub` takes precedence per the module's own logic.
- **CSV artifact expires after 30 days** — download it from the run summary if you need to keep it longer.

---

## Notes

- **DKIM auto-discovery** — If `-Selector` is not provided, selectors in `-DkimSelectors` are tried automatically. Pass `-DkimSelectors @('mysel','selector1')` (alias `-dkim`) to override the default list at runtime — no script editing required.
- **Multi-part TLDs** — Domains like `.co.uk` or `.com.au` are handled for common cases. For complex TLDs, use `-Sub` or `-JustSub` to prevent the domain from being stripped incorrectly.
- **CNAME chaining** — When using `-RecordType CNAME` or `BOTH`, the function follows the CNAME chain to retrieve the final TXT record value.
- **NS records** — Only the first two NS results are returned.
- **Pipeline / bulk input** — Accepts `ValueFromPipeline` and `ValueFromPipelineByPropertyName`. When piping from a CSV, the column must be named `Domain`.
- **Export** — When a format only (`CSV`/`JSON`) is provided, the file is saved to the current directory as `MailRecords_<timestamp>.<ext>`.

---

*Author: Dan Casmas — 07/2023. Tested on Windows PowerShell 5.1 and PowerShell 7 (Windows, Linux, macOS). Portions of code adapted from Jordan W.*
