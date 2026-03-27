#
# Module manifest for module 'Get-MailRecords'
#
# Generated on: 2026-03-26
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'Get-MailRecords.psm1'

    # Version number of this module.
    ModuleVersion     = '2.0.0'

    # Unique identifier for this module.
    GUID              = '86bd1cc5-e00e-49bb-a5b8-f119ff619878'

    # Author of this module.
    Author            = 'Dan Casmas'

    # Copyright statement for this module.
    Copyright         = '(c) 2023 Dan Casmas. Licensed under the GNU General Public License v3.0.'

    # Description of the functionality provided by this module.
    Description       = 'Performs a comprehensive DNS audit of mail-related records (MX, NS, SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT) for a domain, email address, or URL. Includes FCrDNS (PTR) validation on the primary MX host, DKIM selector auto-discovery, TXT/CNAME/BOTH record-type modes, pipeline/bulk input, and CSV/JSON export. Runs on Windows (Resolve-DnsName) and Linux/macOS (dig).'

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
                'BIMI', 'MTA-STS', 'TLS-RPT', 'PTR', 'FCrDNS',
                'DomainHealth', 'EmailSecurity', 'Networking', 'CrossPlatform'
            )

            # URL to the license for this module.
            LicenseUri   = 'https://github.com/dcazman/Get-MailRecords/blob/main/LICENSE'

            # URL to the main website for this project.
            ProjectUri   = 'https://github.com/dcazman/Get-MailRecords'

            # Release notes for this version of the module.
            ReleaseNotes = 'v2.0.0: Major feature release. Added MX_A (A record of the primary MX host), PTR (FCrDNS validation — === match / =/= mismatch), BIMI (default._bimi TXT), MTA-STS (_mta-sts TXT), and TLS-RPT (_smtp._tls TXT) to the output object. Removed the boolean A-record field. -Selector defaults to DKIM auto-discovery; SELECTOR output shows unprovided when DKIM is not found and no selector was given, hinting the user to supply one explicitly. dig path hardened with +time=2 +tries=1 and improved comment/blank-line filtering.'

        }
    }

}
