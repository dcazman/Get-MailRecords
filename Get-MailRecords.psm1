<#
.SYNOPSIS
Performs DNS lookups (A, MX, NS, SPF, DMARC, DKIM) for a domain, email, or URL.

.DESCRIPTION
Checks for common mail-related DNS records on a given domain, email address, or URL.
Supports record types TXT, CNAME, or BOTH for SPF, DMARC, and DKIM.
If a DKIM selector is not provided, common selectors are tried automatically.
Function alias: GMR. Parameter aliases: -d (Domain), -s (Sub), -js (JustSub), -sel (Selector), -dkim (DkimSelectors), -r (RecordType), -srv (Server), -e (Export).

.PARAMETER Domain
The full domain name, email address, or URL to query. Mandatory. Alias: -d

.PARAMETER Sub
Query both the subdomain and the base domain. For example, mail.facebook.com will return results for mail.facebook.com AND facebook.com. Alias: -s

.PARAMETER JustSub
Query only the subdomain — skips the base domain lookup. For example, mail.facebook.com returns results for mail.facebook.com only. Alias: -js

.PARAMETER Selector
Explicit DKIM selector to query. If not provided, selectors in -DkimSelectors are tried automatically. Alias: -sel

.PARAMETER DkimSelectors
List of DKIM selectors to try when no -Selector is given. Defaults to a common set. Override to test custom selectors: -DkimSelectors @('mysel','selector1'). Alias: -dkim

.PARAMETER RecordType
Record type to query for SPF, DMARC, and DKIM. Valid options: 'TXT', 'CNAME', 'BOTH'. Default: 'TXT'. Alias: -r

.PARAMETER Server
DNS server to query. Default: 8.8.8.8. Alias: -srv

.PARAMETER Export
Export results to file. Provide a filename (e.g., 'results.csv', 'output.json') or just the format ('CSV', 'JSON') for auto-generated timestamped filename. Alias: -e

.EXAMPLE
# Get basic mail records for facebook.com
Get-MailRecords -Domain facebook.com
GMR -Domain facebook.com
GMR -d facebook.com

.EXAMPLE
# Query both the subdomain and the base domain
Get-MailRecords -Domain mail.facebook.com -Sub
GMR -d mail.facebook.com -s

.EXAMPLE
# Query only the subdomain, skip the base domain
Get-MailRecords -Domain mail.facebook.com -JustSub
GMR -d mail.facebook.com -js

.EXAMPLE
# Get DKIM record with explicit selector
Get-MailRecords -Domain cnn.facebook.com -Selector face
GMR -d cnn.facebook.com -sel face

.EXAMPLE
# Use a custom DNS server
Get-MailRecords -Domain cnn.com -Server 1.1.1.1
GMR -d cnn.com -srv 1.1.1.1

.EXAMPLE
# Get CNAME records for SPF/DMARC/DKIM
Get-MailRecords -Domain cnn.com -RecordType CNAME
GMR -d cnn.com -r CNAME

.EXAMPLE
# Override the default DKIM selector list with custom selectors
Get-MailRecords -Domain example.com -DkimSelectors @('acmecorp', 'mail2024')
GMR -d example.com -dkim @('acmecorp', 'mail2024')

.EXAMPLE
# Export results to a specific CSV file
Get-MailRecords -Domain example.com -Export results.csv
GMR -d example.com -e results.csv

.EXAMPLE
# Export with auto-generated timestamped filename
Get-MailRecords -Domain example.com -Export CSV
GMR -d example.com -e CSV

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
Tested on Windows PowerShell 5.1 and PowerShell 7 (Windows, Linux, macOS).
Minimum required version: 5.1.
Requires Resolve-DnsName (Windows built-in) or dig (Linux/macOS: install bind-utils or dnsutils).
Function alias: GMR.
Parameter aliases: -d (Domain), -s (Sub), -js (JustSub), -sel (Selector), -dkim (DkimSelectors), -r (RecordType), -srv (Server), -e (Export).
To override DKIM auto-discovery selectors, use -DkimSelectors @('sel1','sel2') or alias -dkim.
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
        [alias ('d')]
        [string]$Domain,

        [parameter(Mandatory = $false, HelpMessage = "Query both the subdomain and the base domain. Example: mail.facebook.com returns results for mail.facebook.com AND facebook.com.")]
        [alias ('s')]
        [switch]$Sub,

        [parameter(Mandatory = $false, HelpMessage = "Query only the subdomain, skip the base domain. Example: mail.facebook.com returns results for mail.facebook.com only.")]
        [alias ('js')]
        [switch]$JustSub,

        [parameter(Mandatory = $false, HelpMessage = "Explicit DKIM selector to query. If not provided, selectors in -DkimSelectors are tried automatically.")]
        [ValidateNotNullOrEmpty()]
        [alias ('sel')]
        [string]$Selector = 'unprovided',

        [parameter(Mandatory = $false, HelpMessage = "DKIM selectors to try when no -Selector is specified. Defaults to a common list. Add your own: -DkimSelectors @('mysel','selector1').")]
        [alias ('dkim')]
        [string[]]$DkimSelectors = @(
            "default", "s", "s1", "s2", "selector1", "selector2", "pps1", "google",
            "everlytickey1", "everlytickey2", "eversrv", "k1", "mxvault", "dkim",
            "mail", "s1024", "s2048", "s4096"
        ),

        [parameter(Mandatory = $false, HelpMessage = "Record type to query for SPF, DMARC, and DKIM. Valid options: TXT, CNAME, BOTH. Default: TXT.")]
        [ValidateSet('TXT', 'CNAME', 'BOTH')]
        [ValidateNotNullOrEmpty()]
        [alias ('r')]
        [string]$RecordType = 'TXT',

        [parameter(Mandatory = $false, HelpMessage = "DNS server to query. Default: 8.8.8.8.")]
        [ValidateNotNullOrEmpty()]
        [alias ('srv')]
        [string]$Server = '8.8.8.8',

        [parameter(Mandatory = $false, HelpMessage = "Export results to file. Provide a filename (e.g., 'results.csv', 'output.json') or just the format ('CSV', 'JSON') for auto-generated timestamped filename.")]
        [alias ('e')]
        [string]$Export
    )

    begin {
        # Determine DNS resolution method first, before any early returns.
        # Resolve-DnsName is Windows built-in; dig is used as a fallback on Linux/macOS.
        if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
            $script:DnsMethod = 'ResolveDnsName'
        }
        elseif (Get-Command -Name dig -ErrorAction SilentlyContinue) {
            $script:DnsMethod = 'dig'
        }
        else {
            $script:DnsMethod = 'none'
            Write-Error "Neither Resolve-DnsName nor dig is available. On Linux/macOS, install bind-utils (RHEL/CentOS) or dnsutils (Debian/Ubuntu) to get dig."
        }

        # Initialize collection for export functionality
        $ExportFormat = $null
        $OutputPath = $null

        if ($Export) {
            $script:AllResults = @()

            # Determine if Export is a filename or just a format (case-insensitive)
            if ($Export -match '\.(csv|json)$') {
                # It's a filename with extension
                $OutputPath = $Export
                $ExportFormat = ($Export -split '\.')[-1].ToUpper()
            }
            elseif ($Export -match '^(csv|json)$') {
                # It's just a format, generate timestamped filename
                $ExportFormat = $Export.ToUpper()
                $timestamp = Get-Date -Format "yyyyMMdd_HHmm"
                $extension = $ExportFormat.ToLower()
                $OutputPath = Join-Path (Get-Location).Path "MailRecords_$timestamp.$extension"
            }
            else {
                Write-Error "Export parameter must be either a filename with .csv or .json extension, or 'CSV'/'JSON' for auto-generated filename."
                return
            }
        }
    }

    process {
        # Abort early if no DNS tool is available
        if ($script:DnsMethod -eq 'none') {
            return $null
        }

        # Cross-platform DNS query wrapper.
        # Uses Resolve-DnsName on Windows; falls back to dig on Linux/macOS.
        # Returns objects with consistent key properties: Type, TTL, Strings, NameHost, NameExchange, Preference, IPAddress.
        function Invoke-DnsQuery {
            param(
                [Parameter(Mandatory = $true)]
                [string]$Name,

                [Parameter(Mandatory = $true)]
                [string]$Type,

                [Parameter(Mandatory = $true)]
                [string]$Server
            )

            if ($script:DnsMethod -eq 'ResolveDnsName') {
                return Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -ErrorAction SilentlyContinue
            }

            # dig fallback for Linux/macOS
            $digArgs = "@$Server", "+noall", "+answer", "-t", $Type.ToUpper(), $Name
            $digOutput = & dig @digArgs 2>$null
            if (-not $digOutput) { return $null }

            $results = [System.Collections.Generic.List[object]]::new()
            foreach ($line in $digOutput) {
                if ([string]::IsNullOrWhiteSpace($line) -or $line -match '^\s*;') { continue }

                # Parse dig answer line: NAME TTL CLASS TYPE DATA
                if ($line -match '^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$') {
                    $recordName = $Matches[1].TrimEnd('.')
                    $ttl = [int]$Matches[2]
                    $recordType = $Matches[3].ToUpper()
                    $data = $Matches[4].Trim()

                    $obj = [PSCustomObject]@{
                        Name = $recordName
                        Type = $recordType
                        TTL  = $ttl
                    }

                    switch ($recordType) {
                        'A' {
                            $obj | Add-Member -NotePropertyName 'IPAddress' -NotePropertyValue $data
                        }
                        'MX' {
                            if ($data -match '^(\d+)\s+(\S+)$') {
                                $obj | Add-Member -NotePropertyName 'Preference' -NotePropertyValue ([int]$Matches[1])
                                $obj | Add-Member -NotePropertyName 'NameExchange' -NotePropertyValue $Matches[2].TrimEnd('.')
                            }
                        }
                        'NS' {
                            $obj | Add-Member -NotePropertyName 'NameHost' -NotePropertyValue $data.TrimEnd('.')
                        }
                        'CNAME' {
                            $obj | Add-Member -NotePropertyName 'NameHost' -NotePropertyValue $data.TrimEnd('.')
                        }
                        'TXT' {
                            # Extract each quoted string segment (handles multi-part TXT records like long DKIM keys)
                            $parts = [regex]::Matches($data, '"([^"]*)"') | ForEach-Object { $_.Groups[1].Value }
                            if (-not $parts) { $parts = @($data) }
                            $obj | Add-Member -NotePropertyName 'Strings' -NotePropertyValue @($parts)
                        }
                    }

                    $results.Add($obj)
                }
            }

            return $results.ToArray()
        }

        # NameServer lookup
        function Get-NS {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Domain,

                [Parameter(Mandatory = $true)]
                [string]$Server
            )

            $NS = Invoke-DnsQuery -Name $Domain -Type 'NS' -Server $Server

            if ([string]::IsNullOrWhiteSpace($NS.NameHost)) {
                return $false
            }

            $OutNS = foreach ($Item in $NS) {
                $Item | Select-Object NameHost, TTL
            }

            [string]$resultsNS = ($OutNS | Select-Object -First 2 | Out-String).TrimEnd("`r`n").Trim()
            return $resultsNS
        }

        # SPF record lookup
        function Get-SPF {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Domain,

                [Parameter(Mandatory = $true)]
                [string]$Server,

                [Parameter(Mandatory = $true)]
                [string]$Type
            )

            $SPF = Invoke-DnsQuery -Name $Domain -Type $Type -Server $Server

            if ($Type -eq 'TXT') {
                $spfRecord = $SPF.Strings | Where-Object { $_ -like "v=spf1*" }
                if ([string]::IsNullOrWhiteSpace($spfRecord)) {
                    return $false
                }
                return $spfRecord
            }
            elseif ($Type -eq 'CNAME') {
                $cnameRecord = $SPF | Where-Object { $_.Type -eq 'CNAME' }
                if ($cnameRecord) {
                    $targetDomain = $cnameRecord.NameHost
                    $targetSPF = Invoke-DnsQuery -Name $targetDomain -Type 'TXT' -Server $Server
                    $spfRecord = $targetSPF.Strings | Where-Object { $_ -like "v=spf1*" }
                    if ($spfRecord) {
                        return "CNAME -> $targetDomain : $spfRecord"
                    }
                    return "CNAME -> $targetDomain (no SPF found)"
                }
                return $false
            }
        }

        # Normalize selector to lowercase for case-insensitive matching
        if ($Selector -ne 'unprovided') {
            $Selector = $Selector.ToLowerInvariant()
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

        # Final cleanup and lowercase normalization
        if ($TestDomain) {
            try {
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

        # Normalize record type to uppercase
        $RecordTypeTest = @()
        if ($RecordType -eq 'BOTH') {
            $RecordTypeTest = @('TXT', 'CNAME')
        }
        else {
            $RecordTypeTest = $RecordType.ToUpper()
        }

        # Check if A record exists
        $resultA = $null -ne (Invoke-DnsQuery -Name $TestDomain -Type 'A' -Server $Server | Where-Object { $_.Type -eq 'A' })

        try {
            # Query the DNS server for MX records
            $mxRecords = Invoke-DnsQuery -Name $TestDomain -Type 'MX' -Server $Server |
            Sort-Object -Property Preference
        }
        catch {
            # Handle errors during the query
            Write-Error "An error occurred while resolving DNS: $_"
            $mxRecords = $null
        }

        # Validate and format MX results outside the try/catch so that
        # Write-Warning is not silently swallowed when -WarningAction Stop is used.
        if ($mxRecords -and $mxRecords.Type -contains 'MX') {
            $formattedRecords = $mxRecords |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameExchange) } |
            Select-Object @{n = "Name"; e = { $_.NameExchange } },
            @{n = "Preference"; e = { $_.Preference } },
            @{n = "TTL"; e = { $_.TTL } }
            $resultmx = ($formattedRecords | Out-String).TrimEnd("`r`n").Trim()
        }
        else {
            Write-Warning "No MX records found for domain: $Domain"
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
            $DMARC = Invoke-DnsQuery -Name "_dmarc.$TestDomain" -Type $TempType -Server $Server

            if (-not $DMARC) {
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
                        $targetDMARC = Invoke-DnsQuery -Name $targetDomain -Type 'TXT' -Server $Server
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
                # Get DKIM record if it exists
                $DKIM = Invoke-DnsQuery -Name "$($Selector)._domainkey.$($TestDomain)" -Type $TempType -Server $Server |
                Where-Object { $_.Type -eq $TempType }

                if (-not $DKIM) {
                    $resultdkim = $false
                }
                else {
                    if ($TempType -eq 'TXT') {
                        foreach ($Item in $DKIM) {
                            if ($Item.Type -eq 'TXT' -and $Item.Strings -match "v=DKIM1") {
                                $resultdkim = [string]$Item.Strings
                                break
                            }
                        }
                    }
                    elseif ($TempType -eq 'CNAME') {
                        $cnameRecord = $DKIM | Where-Object { $_.Type -eq 'CNAME' }
                        if ($cnameRecord) {
                            $targetDomain = $cnameRecord.NameHost
                            $targetDKIM = Invoke-DnsQuery -Name $targetDomain -Type 'TXT' -Server $Server
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

            # Auto-discover DKIM selector if not provided
            if ($Selector -eq 'unprovided') {
                # Break the loop if DKIM is found
                $BreakFlag = $false
                foreach ($line in $DkimSelectors) {
                    $DKIM = $null
                    $DKIM = Invoke-DnsQuery -Name "$($line)._domainkey.$($TestDomain)" -Type $TempType -Server $Server |
                    Where-Object { $_.Type -eq $TempType }

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
                            $targetDKIM = Invoke-DnsQuery -Name $targetDomain -Type 'TXT' -Server $Server
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

            # If Sub is true, also query the base/parent domain
            if ($Sub -eq $true -and ($TestDomain.Split('.').count -gt 2)) {
                # Derive the parent domain explicitly from the already-parsed domain
                $tParts = $TestDomain.Split('.')
                $parentDomain = if ($tParts.Count -gt 2 -and $tParts[-2].Length -eq 2 -and $tParts[-1].Length -le 3) {
                    $tParts[-3..-1] -join '.'
                }
                else {
                    $tParts[-2, -1] -join '.'
                }
                # Skip if stripping produced the same domain (e.g. multi-part TLDs like .co.uk)
                if ($parentDomain -ne $TestDomain) {
                    $subOutput = Get-MailRecords -Domain $parentDomain -Server $Server -RecordType $RecordType -Selector $SelectorHold
                    if ($Export) {
                        $script:AllResults += $subOutput
                    }
                    else {
                        $subOutput
                    }
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
