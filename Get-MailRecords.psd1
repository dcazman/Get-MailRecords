#
# Module manifest for module 'Get-MailRecords'
#
# Generated on: 2026-02-24
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'Get-MailRecords.psm1'

    # Version number of this module.
    ModuleVersion     = '1.0.0'

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

            # URL to the license for this module.
            LicenseUri   = 'https://github.com/dcazman/Get-MailRecords/blob/main/LICENSE'

            # URL to the main website for this project.
            ProjectUri   = 'https://github.com/dcazman/Get-MailRecords'

            # Release notes for this version of the module.
            ReleaseNotes = 'Initial release. Supports A, MX, NS, SPF, DMARC, and DKIM lookups. Cross-platform: Windows (Resolve-DnsName) and Linux/macOS (dig). DKIM selector auto-discovery, subdomain handling, pipeline input, and CSV/JSON export.'

        }
    }

}
