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

## Notes

- **DKIM auto-discovery** — If `-Selector` is not provided, selectors in `-DkimSelectors` are tried automatically. Pass `-DkimSelectors @('mysel','selector1')` (alias `-dkim`) to override the default list at runtime — no script editing required.
- **Multi-part TLDs** — Domains like `.co.uk` or `.com.au` are handled for common cases. For complex TLDs, use `-Sub` or `-JustSub` to prevent the domain from being stripped incorrectly.
- **CNAME chaining** — When using `-RecordType CNAME` or `BOTH`, the function follows the CNAME chain to retrieve the final TXT record value.
- **NS records** — Only the first two NS results are returned.
- **Pipeline / bulk input** — Accepts `ValueFromPipeline` and `ValueFromPipelineByPropertyName`. When piping from a CSV, the column must be named `Domain`.
- **Export** — When a format only (`CSV`/`JSON`) is provided, the file is saved to the current directory as `MailRecords_<timestamp>.<ext>`.

---

*Author: Dan Casmas — 07/2023. Tested on Windows PowerShell 5.1 and PowerShell 7 (Windows, Linux, macOS). Portions of code adapted from Jordan W.*
