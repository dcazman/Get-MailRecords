#
# Module manifest for module 'Get-MailRecords'
#
# Generated on: 2026-02-24
#
@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'Get-MailRecords.psm1'
    # Version number of this module.
    ModuleVersion     = '1.1.3'
    # Unique identifier for this module.
    GUID              = '86bd1cc5-e00e-49bb-a5b8-f119ff619878'
    # Author of this module.
    Author            = 'Dan Casmas'
    # Copyright statement for this module.
    Copyright         = '(c) 2023 Dan Casmas. Licensed under the GNU General Public License v3.0.'
    # Description of the functionality provided by this module.
    Description       = 'Performs DNS lookups for mail-related records (A, MX, NS, SPF, DMARC, DKIM) on a given domain, email address, or URL. Supports TXT, CNAME, and BOTH record types, DKIM auto-discovery, pipeline/bulk input, and CSV/JSON export.'
    # Minimum version of the Windows PowerShell engine required by this module.
    PowerShellVersion = '5.1'
    # Functions to export from this module.
    FunctionsToExport = @('Get-MailRecords')
    # Aliases to export from this module.
    AliasesToExport   = @('GMR')
    # Cmdlets to export from this module.
    CmdletsToExport   = @()
    # Variables to export from this module.
    VariablesToExport = @()
    # Private data to pass to the module specified in RootModule.
    PrivateData       = @{
        PSData = @{
            # Tags applied to this module for PSGallery discoverability.
            Tags         = @(
                'DNS', 'Mail', 'Email', 'SPF', 'DMARC', 'DKIM', 'MX', 'NS',
                'DomainHealth', 'EmailSecurity', 'Networking', 'CrossPlatform'
            )
            Unlisted = $true
            # URL to the license for this module.
            LicenseUri   = 'https://github.com/dcazman/Get-MailRecords/blob/main/LICENSE'
            # URL to the main website for this project.
            ProjectUri   = 'https://github.com/dcazman/Get-MailRecords'
            # Release notes for this version of the module.
            ReleaseNotes = @'
## v1.1.2 — 2026-03-20

### Bug Fixes
- **Fixed terminating error when using `-RecordType CNAME`**
  `$RecordTypeTest` was assigned as a bare `[string]` for single record types
  (TXT or CNAME). When piped into `ForEach-Object`, the pipeline-unwrapped
  value failed parameter binding on the `-Type [string]` argument of `Get-SPF`,
  throwing: *"Cannot convert value to type System.String."*
  `$RecordTypeTest` is now always cast to `@(...)`, consistent with the `BOTH`
  branch. Affected all invocations with `-RecordType CNAME` or explicit
  `-RecordType TXT`.

- **Replaced `Write-Warning` with `Write-Verbose` for missing MX records**
  Non-mail subdomains (e.g. landing pages, tracking links) legitimately have no
  MX records. The previous `WARNING: No MX records found` message was alarming
  and misleading for these cases. The message is now emitted via `Write-Verbose`
  and visible only when `-Verbose` is passed. The output object still reflects
  `MX = $false` as before.

### Tests
- Added `gmr.Tests.ps1` (Pester v5) covering:
  - No terminating error on `-RecordType CNAME` with no records present
  - Output object returned with `SPF_CNAME`, `DMARC_CNAME`, `DKIM_CNAME`,
    and `MX` all set to `$false` when nothing is found
  - No `WarningRecord` emitted for missing MX on non-mail subdomains
  - CNAME → SPF resolution returns the expected `CNAME -> target : record` string
  - `-RecordType BOTH` returns exactly two output objects (TXT then CNAME)
  - `-RecordType TXT` default behaviour is unaffected (regression guard)

---

## v1.1.1
- Minor fix release (see prior history).

## v1.1.0
- Added `-DkimSelectors` parameter (alias `-dkim`) to allow runtime override of
  the DKIM auto-discovery selector list without editing the script.
- Improved parameter ordering (Sub/JustSub grouped, Selector/DkimSelectors grouped).
- Fixed misleading HelpMessages and comment-based help.
- Removed duplicate example.
- All aliases documented in Description and Notes.
'@
        }
    }
}
