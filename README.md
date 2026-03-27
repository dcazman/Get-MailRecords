# Get-MailRecords

[![PSGallery Version](https://img.shields.io/powershellgallery/v/Get-MailRecords)](https://www.powershellgallery.com/packages/Get-MailRecords)
[![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/Get-MailRecords)](https://www.powershellgallery.com/packages/Get-MailRecords)

Performs a comprehensive DNS audit of mail-related records for a domain, email address, or URL.
Checks **MX, NS, SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT**, and performs **FCrDNS (PTR)** validation on the primary MX host.
Supports bulk/pipeline input and CSV/JSON export.

**Function alias:** `GMR` &nbsp;|&nbsp; **Repo:** https://github.com/dcazman/Get-MailRecords

---

## What's New in v2.0.0

Major feature release.

- **Added** `MX_A` — A record of the primary (lowest-preference) MX host
- **Added** `PTR` — FCrDNS validation (`===` forward-confirmed match / `=/=` mismatch)
- **Added** `BIMI` — `default._bimi` TXT record lookup
- **Added** `MTA-STS` — `_mta-sts` TXT record lookup
- **Added** `TLS-RPT` — `_smtp._tls` TXT record lookup
- **Removed** the boolean A-record field from the output object
- **Hardened** `dig` path with `+time=2 +tries=1` and improved comment/blank-line filtering

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
| `-Sub`           | `-s`    | Switch   | Query the subdomain **and** the base domain. `mail.example.com` returns results for both `mail.example.com` and `example.com`. |
| `-JustSub`       | `-js`   | Switch   | Query only the domain exactly as provided — skips base domain extraction. |
| `-Selector`      | `-sel`  | String   | Explicit DKIM selector to query. If omitted, selectors in `-DkimSelectors` are tried automatically. |
| `-DkimSelectors` | `-dkim` | String[] | List of DKIM selectors to try when no `-Selector` is given. Defaults to a built-in common set. Pass your own to override or extend. |
| `-RecordType`    | `-r`    | String   | Record type to query for SPF, DMARC, and DKIM. Valid: `TXT` (default), `CNAME`, `BOTH`. |
| `-Server`        | `-srv`  | String   | DNS server to query. Default: `8.8.8.8`. |
| `-Export`        | `-e`    | String   | Export results to file. Provide a filename (`results.csv`, `output.json`) or just the format (`CSV`, `JSON`) for an auto-generated timestamped filename. |

## Examples

#### Basic lookup

```powershell
Get-MailRecords -Domain example.com
GMR -d example.com
```

#### Query subdomain and base domain together

```powershell
Get-MailRecords -Domain mail.example.com -Sub
GMR -d mail.example.com -s
```

#### Query only the subdomain

```powershell
Get-MailRecords -Domain mail.example.com -JustSub
GMR -d mail.example.com -js
```

#### Provide a DKIM selector explicitly

```powershell
Get-MailRecords -Domain example.com -Selector selector1
GMR -d example.com -sel selector1
```

#### Override the DKIM selector auto-discovery list

```powershell
Get-MailRecords -Domain example.com -DkimSelectors @('acmecorp', 'mail2024')
GMR -d example.com -dkim @('acmecorp', 'mail2024')
```

#### Query CNAME records for SPF / DMARC / DKIM

```powershell
Get-MailRecords -Domain example.com -RecordType CNAME
GMR -d example.com -r CNAME
```

#### Query both TXT and CNAME record types

```powershell
Get-MailRecords -Domain example.com -RecordType BOTH
GMR -d example.com -r BOTH
```

#### Use a custom DNS server

```powershell
Get-MailRecords -Domain example.com -Server 1.1.1.1
GMR -d example.com -srv 1.1.1.1
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
# Saves as: MailRecords_20260101_1430.json
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

| Property                    | Description |
| :-------------------------- | :---------- |
| `DOMAIN`                    | The domain that was queried |
| `SERVER`                    | The DNS server used |
| `RECORDTYPE`                | The record type queried (`TXT` or `CNAME`) |
| `MX_A`                      | Resolved IP address of the primary (lowest-preference) MX host, or `None` |
| `PTR`                       | FCrDNS result: `<hostname> === <ip>` (forward-confirmed match) or `<hostname> =/= <ip>` (mismatch), or `None` |
| `MX`                        | MX records formatted as `hostname [pref N]`, sorted by preference |
| `SPF_TXT` / `SPF_CNAME`     | SPF record value, or `None` if not found |
| `DMARC_TXT` / `DMARC_CNAME` | DMARC record value, or `None` if not found |
| `DKIM_TXT` / `DKIM_CNAME`   | DKIM record value, or `None` if not found |
| `SELECTOR`                  | The DKIM selector that matched, or the selector provided |
| `BIMI`                      | BIMI record (`default._bimi`) value, or `None` |
| `NS_First2`                 | First two NS records with TTLs |
| `MTA_STS`                   | MTA-STS policy record (`_mta-sts`) value, or `None` |
| `TLS_RPT`                   | TLS reporting record (`_smtp._tls`) value, or `None` |

## Notes

- **PTR / FCrDNS** — Resolves the primary MX host to an IP (MX_A), then performs a reverse lookup and re-resolves the PTR hostname forward. `===` means the IP matches (forward-confirmed); `=/=` means it does not.
- **BIMI** — Queries `default._bimi.<domain>` for a `v=BIMI1` TXT record. Requires a valid DMARC policy to be honoured by receivers.
- **MTA-STS** — Queries `_mta-sts.<domain>` for a `v=STSv1` TXT record indicating an MTA-STS policy is published.
- **TLS-RPT** — Queries `_smtp._tls.<domain>` for a `v=TLSRPTv1` TXT record used to receive TLS failure reports.
- **DKIM auto-discovery** — If `-Selector` is not provided, selectors in `-DkimSelectors` are tried automatically. Pass `-DkimSelectors @('mysel','selector1')` (alias `-dkim`) to override the default list at runtime.
- **Multi-part TLDs** — Domains like `.co.uk` or `.com.au` are handled for common cases. For complex TLDs, use `-Sub` or `-JustSub` to prevent the domain from being stripped incorrectly.
- **CNAME chaining** — When using `-RecordType CNAME` or `BOTH`, the function follows the CNAME chain to retrieve the final TXT record value.
- **NS records** — Only the first two NS results are returned.
- **Pipeline / bulk input** — Accepts `ValueFromPipeline`. When piping from a CSV, the column must be named `Domain`.
- **Export** — When a format only (`CSV`/`JSON`) is provided, the file is saved to the current directory as `MailRecords_<timestamp>.<ext>`.

---

*Author: Dan Casmas — 07/2023. Tested on Windows PowerShell 5.1 and PowerShell 7 (Windows, Linux, macOS).*
