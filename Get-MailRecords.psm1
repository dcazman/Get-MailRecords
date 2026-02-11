<#
.SYNOPSIS
Performs DNS lookups (A, MX, NS, SPF, DMARC, DKIM) for a domain, email, or URL.

.DESCRIPTION
Checks for common mail-related DNS records on a given domain, email address, or URL.  
Supports record types TXT, CNAME, or BOTH for SPF, DMARC, and DKIM.  
If a DKIM selector is not provided, common selectors are tried automatically.  
Alias: GMR. Add to your PowerShell profile for convenience.

.PARAMETER Domain
The full domain name, email address, or URL to query. Mandatory.

.PARAMETER Sub
Include subdomains in the checks.

.PARAMETER JustSub
Return only subdomain information (exclude parent domain).

.PARAMETER Selector
The DKIM selector to use. If not provided, common selectors are tried automatically.

.PARAMETER RecordType
Record type(s) to query for SPF, DMARC, and DKIM.  
Valid options: 'TXT', 'CNAME', 'BOTH'. Default: 'TXT'.

.PARAMETER Server
DNS server to query. Default: 8.8.8.8.

.EXAMPLE
# Get basic mail records for facebook.com
Get-MailRecords -Domain facebook.com
GMR -Domain facebook.com

.EXAMPLE
# Include subdomains
Get-MailRecords -Domain facebook.com -Sub

.EXAMPLE
# Get DKIM record with explicit selector
Get-MailRecords -Domain cnn.facebook.com -Selector face

.EXAMPLE
# Use a custom DNS server
Get-MailRecords -Domain cnn.com -Server 1.1.1.1

.EXAMPLE
# Get CNAME records for SPF/DMARC/DKIM
Get-MailRecords -Domain cnn.com -RecordType CNAME

.EXAMPLE
# Get only subdomain records (exclude parent domain)
Get-MailRecords -Domain mail.facebook.com -JustSub

.EXAMPLE
# Export results to a specific CSV file
Get-MailRecords -Domain example.com -Export results.csv

.EXAMPLE
# Export with auto-generated timestamped filename
Get-MailRecords -Domain example.com -Export CSV

.EXAMPLE
# Check multiple domains via pipeline and export to JSON
"google.com", "microsoft.com", "amazon.com" | Get-MailRecords -Export output.json

.EXAMPLE
# Bulk check from CSV file and export results
Import-Csv domains.csv | Get-MailRecords -Export results.csv

.EXAMPLE
# Prompt for domain interactively
GMR

.LINK
https://github.com/dcazman/Get-MailRecords

.NOTES
Author: Dan Casmas (07/2023)
Tested on Windows PowerShell 5.1 and PowerShell 7 (Windows only).
Minimum required version: 5.1.
Alias: GMR.
To add more DKIM selectors, edit $DkimSelectors near the top of the script.
Only the first two NS results are returned.
CNAME record types will follow the CNAME chain to retrieve the final TXT record value.
Note: Multi-part TLDs (e.g., .co.uk, .com.au) are handled for common cases, but use -Sub for complex domains.
Portions of code adapted from Jordan W.
#>
function Get-MailRecords {
    [Alias("GMR")]
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, HelpMessage = "Enter the full domain name, email address, or URL.", Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                if ($_ -like "*.*") {
                    return $true
                }
                else {
                    throw [System.Management.Automation.ValidationMetadataException] "Enter the full domain name, email address, or URL."
                }
            })]
        [string]$Domain,

        [parameter(Mandatory = $false, HelpMessage = "Allow subdomain. Example: mail.facebook.com")]
        [switch]$Sub,

        [parameter(Mandatory = $false, HelpMessage = "DKIM selector. DKIM won't be checked without this string.")]
        [ValidateNotNullOrEmpty()]
        [string]$Selector = 'unprovided',

        [parameter(Mandatory = $false, HelpMessage = "Looks for record type TXT or CNAME or BOTH for SPF, DMARC, and DKIM if -Selector is used. The default record type is TXT.")]
        [ValidateSet('TXT', 'CNAME', 'BOTH')]
        [ValidateNotNullOrEmpty()]
        [string]$RecordType = 'TXT',

        [parameter(Mandatory = $false, HelpMessage = "Server to query. The default is 8.8.8.8")]
        [ValidateNotNullOrEmpty()]
        [string]$Server = '8.8.8.8',

        [parameter(Mandatory = $false, HelpMessage = "Output is only sub domain Example: mail.facebook.com")]
        [switch]$JustSub,

        [parameter(Mandatory = $false, HelpMessage = "Export results to file. Provide a filename (e.g., 'results.csv', 'output.json') or just the format ('CSV', 'JSON') for auto-generated timestamped filename.")]
        [string]$Export
    )

    begin {
        # Initialize collection for export functionality
        $ExportFormat = $null
        $OutputPath = $null

        if ($Export) {
            $script:AllResults = @()

            # Determine if Export is a filename or just a format
            if ($Export -match '\.(csv|json)$') {
                # It's a filename with extension
                $OutputPath = $Export
                $ExportFormat = ($Export -split '\.')[-1].ToUpper()
            }
            elseif ($Export -match '^(CSV|JSON)$') {
                # It's just a format, generate timestamped filename
                $ExportFormat = $Export.ToUpper()
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $extension = $ExportFormat.ToLower()
                $OutputPath = ".\MailRecords_$timestamp.$extension"
            }
            else {
                Write-Error "Export parameter must be either a filename with .csv or .json extension, or 'CSV'/'JSON' for auto-generated filename."
                return
            }
        }
    }

    process {
        # Initialize DKIM selectors
        $DkimSelectors = @(
            "default", "s", "s1", "s2", "selector1", "selector2", "pps1", "google", "everlytickey1", "everlytickey2", "eversrv", "k1", "mxvault", "dkim", "mail", "s1024", "s2048", "s4096"
        )

        # Check if Resolve-DnsName cmdlet is available
        if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
            Write-Error "The Resolve-DnsName cmdlet is not available. Unable to continue."
            return $null
        }

        # Validate and parse the input domain
        $TestDomain = try {
            ([System.Uri]$Domain).Host.TrimStart('www.')
        }
        catch {
            try {
                ([Net.Mail.MailAddress]$Domain).Host
            }
            catch {
                $Domain
            }
        }

        # Final cleanup and validation
        if ($TestDomain) {
            try {
                # Only remove '@' from the parsed domain (rare edge cases)
                $TestDomain = $TestDomain.Replace('@', '').Trim().ToLowerInvariant()
            }
            catch {
                Write-Error "Problem with $Domain as entered. Please read the command help."
                return $null
            }
        }
        else {
            Write-Error "Problem with $Domain as entered. Please read the command help."
            return $null
        }

        # Extract the base domain (handles most cases, but not multi-part TLDs like .co.uk)
        # For complex TLDs, use the -Sub parameter to preserve the full domain
        if (-not $Sub -and -not $JustSub) {
            $parts = $TestDomain.Split(".")
            # Basic handling: if more than 3 parts and second-to-last is short (2 chars), keep 3 parts
            # This catches common cases like example.co.uk, but not all scenarios
            if ($parts.Count -gt 2 -and $parts[-2].Length -eq 2 -and $parts[-1].Length -le 3) {
                $TestDomain = $parts[-3..-1] -join "."
            }
            else {
                $TestDomain = $parts[-2, -1] -join "."
            }
        }

        # Initialize DKIM result
        $resultdkim = $false

        #NameServer function
        function Get-NS {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Domain,

                [Parameter(Mandatory = $true)]
                [string]$Server
            )

            # Resolve DNS name for the given domain and type 'NS' using the specified DNS server
            $NS = Resolve-DnsName -Name $Domain -Type 'NS' -Server $Server -DnsOnly -ErrorAction SilentlyContinue

            # Check if the DNS resolution was successful and if the NameHost property is not empty
            if ([string]::IsNullOrWhiteSpace($NS.NameHost)) {
                return $false    # If unsuccessful, return false
            }

            # Iterate through each resolved DNS record and select NameHost and TTL properties
            $OutNS = foreach ($Item in $NS) {
                $Item | Select-Object NameHost, TTL
            }

            # Convert the selected DNS records to a formatted string, trimming any trailing whitespace
            [string]$resultsNS = ($OutNS | Select-Object -First 2 | Out-String).TrimEnd("`r`n").Trim()

            return $resultsNS   # Return the formatted DNS records as a string
        }

        # Define function to get SPF record
        function Get-SPF {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Domain,

                [Parameter(Mandatory = $true)]
                [string]$Server,

                [Parameter(Mandatory = $true)]
                [string]$Type
            )

            # Resolve the DNS name
            $SPF = Resolve-DnsName -Name $Domain -Type $Type -Server $Server -DnsOnly -ErrorAction SilentlyContinue

            # Handle TXT vs CNAME records differently
            if ($Type -eq 'TXT') {
                # Check for SPF strings in TXT records
                $spfRecord = $SPF.Strings | Where-Object { $_ -like "v=spf1*" } -ErrorAction SilentlyContinue

                # Return the SPF string if found, otherwise return $false
                if ([string]::IsNullOrWhiteSpace($spfRecord)) {
                    return $false
                }
                return $spfRecord
            }
            elseif ($Type -eq 'CNAME') {
                # For CNAME, check if a CNAME record exists
                $cnameRecord = $SPF | Where-Object { $_.Type -eq 'CNAME' }
                if ($cnameRecord) {
                    # Follow the CNAME to get the actual SPF record
                    $targetDomain = $cnameRecord.NameHost
                    $targetSPF = Resolve-DnsName -Name $targetDomain -Type TXT -Server $Server -DnsOnly -ErrorAction SilentlyContinue
                    $spfRecord = $targetSPF.Strings | Where-Object { $_ -like "v=spf1*" } -ErrorAction SilentlyContinue
                    if ($spfRecord) {
                        return "CNAME -> $targetDomain : $spfRecord"
                    }
                    return "CNAME -> $targetDomain (no SPF found)"
                }
                return $false
            }
        }

        # If both record types are specified, create an array; otherwise, use the specified type
        $RecordTypeTest = @()
        if ($RecordType -eq 'BOTH') {
            $RecordTypeTest = @('TXT', 'CNAME')
        }
        else {
            $RecordTypeTest = $RecordType.ToUpper()
        }

        # Check if A record exists
        $resultA = $null -ne (Resolve-DnsName -Name $TestDomain -Type 'A' -Server $Server -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq 'a' })

        try {
            # Query the DNS server for MX records
            $mxRecords = Resolve-DnsName -Name $TestDomain -Type 'MX' -Server $Server -DnsOnly -ErrorAction Stop |
            Sort-Object -Property Preference

            # Validate if MX records exist
            if ($mxRecords -and $mxRecords.Type -contains 'MX') {
                # Format and return the MX records
                $formattedRecords = $mxRecords |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameExchange) } |
                Select-Object @{n = "Name"; e = { $_.NameExchange } },
                @{n = "Preference"; e = { $_.Preference } },
                @{n = "TTL"; e = { $_.TTL } }
                # Return as a clean, trimmed string
                $resultmx = ($formattedRecords | Out-String).TrimEnd("`r`n").Trim()
            }
            else {
                # No MX records found
                Write-Warning "No MX records found for domain: $Domain"
                $resultmx = $false
            }
        }
        catch {
            # Handle errors during the query
            Write-Error "An error occurred while resolving DNS: $_"
            $resultmx = $false
        }

        # Hold the original selector value
        $SelectorHold = $Selector

        # Loop through specified record types
        $Output = $RecordTypeTest | ForEach-Object {
            $TempType = $_

            # Get NS records
            $resultsNS = Get-NS -Domain $TestDomain -Server $Server

            # Get SPF record
            $resultspf = Get-SPF -Domain $TestDomain -Server $Server -Type $TempType

            # Get DMARC record
            $DMARC = Resolve-DnsName -Name "_dmarc.$TestDomain" -Type $TempType -Server $Server -DnsOnly -ErrorAction SilentlyContinue

            if ([string]::IsNullOrWhiteSpace($DMARC)) {
                $resultdmarc = $false
            }
            else {
                if ($TempType -eq 'TXT') {
                    $resultdmarc = ($DMARC.Strings -like "v=DMARC1*") -join ' '
                    if ([string]::IsNullOrWhiteSpace($resultdmarc)) {
                        $resultdmarc = $false
                    }
                }
                elseif ($TempType -eq 'CNAME') {
                    $cnameRecord = $DMARC | Where-Object { $_.Type -eq 'CNAME' }
                    if ($cnameRecord) {
                        $targetDomain = $cnameRecord.NameHost
                        $targetDMARC = Resolve-DnsName -Name $targetDomain -Type TXT -Server $Server -DnsOnly -ErrorAction SilentlyContinue
                        $dmarcRecord = ($targetDMARC.Strings -like "v=DMARC1*") -join ' '
                        if ($dmarcRecord) {
                            $resultdmarc = "CNAME -> $targetDomain : $dmarcRecord"
                        }
                        else {
                            $resultdmarc = "CNAME -> $targetDomain (no DMARC found)"
                        }
                    }
                    else {
                        $resultdmarc = $false
                    }
                }
            }

            # Start of DKIM checking
            if ($Selector -ne 'unprovided') {
                # get DKIM record if exist
                $DKIM = Resolve-DnsName -Type $($TempType) -Name "$($Selector)._domainkey.$($TestDomain)" -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq $($TempType) }

                if ([string]::IsNullOrWhiteSpace($DKIM)) {
                    $resultdkim = $false
                }
                else {
                    if ($TempType -eq 'TXT') {
                        foreach ($Item in $DKIM) {
                            if ($Item.type -eq 'TXT' -and $Item.Strings -match "v=DKIM1") {
                                $resultdkim = [string]$Item.Strings
                                break
                            }
                        }
                    }
                    elseif ($TempType -eq 'CNAME') {
                        $cnameRecord = $DKIM | Where-Object { $_.Type -eq 'CNAME' }
                        if ($cnameRecord) {
                            $targetDomain = $cnameRecord.NameHost
                            $targetDKIM = Resolve-DnsName -Name $targetDomain -Type TXT -Server $Server -DnsOnly -ErrorAction SilentlyContinue
                            $dkimRecord = $targetDKIM | Where-Object { $_.Strings -match "v=DKIM1" }
                            if ($dkimRecord) {
                                $resultdkim = "CNAME -> $targetDomain : $([string]$dkimRecord.Strings)"
                            }
                            else {
                                $resultdkim = "CNAME -> $targetDomain (no DKIM found)"
                            }
                        }
                        else {
                            $resultdkim = $false
                        }
                    }
                }
            }

            # Look for DKIM if not provided
            if ($Selector -eq 'unprovided') {
                # Break the loop if DKIM is found.
                $BreakFlag = $false
                foreach ($line in $DkimSelectors) {
                    # get DKIM record if exist
                    $DKIM = $null
                    $DKIM = Resolve-DnsName -Type $($TempType) -Name "$($line)._domainkey.$($TestDomain)" -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq $TempType }

                    if ($TempType -eq 'TXT') {
                        $DKIM = $DKIM | Where-Object { $_.Strings -match "v=DKIM1" }
                        foreach ($Item in $DKIM) {
                            [string]$resultdkim = $Item.Strings
                            $Selector = $line
                            $BreakFlag = $true
                            break
                        }
                    }
                    elseif ($TempType -eq 'CNAME') {
                        $cnameRecord = $DKIM | Where-Object { $_.Type -eq 'CNAME' }
                        if ($cnameRecord) {
                            $targetDomain = $cnameRecord.NameHost
                            $targetDKIM = Resolve-DnsName -Name $targetDomain -Type TXT -Server $Server -DnsOnly -ErrorAction SilentlyContinue
                            $dkimRecord = $targetDKIM | Where-Object { $_.Strings -match "v=DKIM1" }
                            if ($dkimRecord) {
                                $resultdkim = "CNAME -> $targetDomain : $([string]$dkimRecord.Strings)"
                                $Selector = $line
                                $BreakFlag = $true
                            }
                        }
                    }

                    if ($BreakFlag) {
                        break
                    }
                }
            }

            # Reset selector if DKIM not found
            if ($resultdkim -eq $false) {
                $Selector = $SelectorHold
            }

            [PSCustomObject]@{
                A                 = $resultA
                MX                = $resultmx
                "SPF_$TempType"   = $resultspf
                "DMARC_$TempType" = $resultdmarc
                "DKIM_$TempType"  = $resultdkim
                SELECTOR          = $Selector
                DOMAIN            = $TestDomain
                RECORDTYPE        = $TempType
                SERVER            = $Server
                NS_First2         = $resultsNS
            }
        }

        if ($JustSub) {
            if ($Export) {
                $script:AllResults += $Output
            }
            else {
                return $Output
            }
        }
        else {
            if ($Export) {
                $script:AllResults += $Output
            }
            else {
                $Output
            }

            # If Sub is true, recursively call the function with the original parameters
            if ($Sub -eq $true -and ($Domain.Split('.').count -gt 2)) {
                $subOutput = Get-MailRecords -Domain $Domain -Server $Server -RecordType $RecordType -Selector $SelectorHold
                if ($Export) {
                    $script:AllResults += $subOutput
                }
                else {
                    $subOutput
                }
            }
        }
    }

    end {
        # Export results if requested
        if ($ExportFormat -and $script:AllResults.Count -gt 0) {
            try {
                switch ($ExportFormat) {
                    'CSV' {
                        $script:AllResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force
                        Write-Host "Results exported to: $OutputPath" -ForegroundColor Green
                    }
                    'JSON' {
                        $script:AllResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Force
                        Write-Host "Results exported to: $OutputPath" -ForegroundColor Green
                    }
                }
            }
            catch {
                Write-Error "Failed to export results: $_"
            }
        }
    }
}
