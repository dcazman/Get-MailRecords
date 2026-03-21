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
Try it now — no install required
gmr.thecasmas.com
Enter a domain, get your mail DNS records instantly. Works in any browser, on any device. No information saved
Portions of code adapted from Jordan W.
#>
function Get-MailRecords {
    [Alias("GMR")]
    [CmdletBinding()]
    param (
        # Accepts a bare domain (example.com), an email address (user@example.com),
        # or a full URL (https://example.com). Parsed into a clean hostname before querying.
        # Accepts pipeline input by value or by property name for bulk lookups.
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

        # When set, queries the subdomain supplied AND its base domain.
        # e.g. -Domain mail.example.com -Sub returns results for both
        # mail.example.com and example.com.
        [parameter(Mandatory = $false)]
        [alias ('s')]
        [switch]$Sub,

        # When set, queries ONLY the domain exactly as supplied — no base domain lookup.
        # Useful for landing page or tracking subdomains that are not mail senders.
        [parameter(Mandatory = $false)]
        [alias ('js')]
        [switch]$JustSub,

        # Explicit DKIM selector to query (e.g. 'selector1', 'google').
        # If omitted, DKIM auto-discovery runs through the $DkimSelectors list.
        # Internal sentinel value 'unprovided' indicates no selector was passed.
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [alias ('sel')]
        [string]$Selector = 'unprovided',

        # List of DKIM selectors to try during auto-discovery when no explicit
        # -Selector is given. Covers common selectors used by major ESPs and platforms.
        # Can be overridden at runtime to test a custom set without editing the module.
        [parameter(Mandatory = $false)]
        [alias ('dkim')]
        [string[]]$DkimSelectors = @(
            "default", "s", "s1", "s2", "selector1", "selector2", "pps1", "google",
            "everlytickey1", "everlytickey2", "eversrv", "k1", "mxvault", "dkim",
            "mail", "s1024", "s2048", "s4096"
        ),

        # Controls which DNS record type is queried for SPF, DMARC, and DKIM.
        # TXT  — standard lookup (default).
        # CNAME — follows CNAMEs to their TXT target (used by some DNS providers
        #         such as Proofpoint and Microsoft 365 for flattened SPF).
        # BOTH  — runs TXT and CNAME passes and returns one output object per pass.
        [parameter(Mandatory = $false)]
        [ValidateSet('TXT', 'CNAME', 'BOTH')]
        [ValidateNotNullOrEmpty()]
        [alias ('r')]
        [string]$RecordType = 'TXT',

        # DNS server to query. Defaults to Google Public DNS (8.8.8.8).
        # Can be overridden to test against an authoritative or internal resolver.
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [alias ('srv')]
        [string]$Server = '8.8.8.8',

        # Optional export path or format string.
        # Pass a filename with .csv or .json extension to write to that path,
        # or pass 'CSV' / 'JSON' to auto-generate a timestamped file in the
        # current directory. Collects all pipeline results before writing.
        [parameter(Mandatory = $false)]
        [alias ('e')]
        [string]$Export
    )

    # -- BEGIN -----------------------------------------------------------------
    # Runs once before pipeline input is processed.
    # Determines which DNS resolution method is available and validates the
    # Export parameter so any format errors fail fast before DNS queries start.
    begin {
        # Prefer Resolve-DnsName (Windows / PowerShell 7 on Windows).
        # Fall back to dig (Linux / macOS). Fail clearly if neither is present.
        if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
            $script:DnsMethod = 'ResolveDnsName'
        }
        elseif (Get-Command -Name dig -ErrorAction SilentlyContinue) {
            $script:DnsMethod = 'dig'
        }
        else {
            $script:DnsMethod = 'none'
            Write-Error "Neither Resolve-DnsName nor dig is available."
        }

        $ExportFormat = $null
        $OutputPath = $null

        if ($Export) {
            # Initialise the collection that accumulates results across all
            # pipeline inputs when exporting. Written in the end block.
            $script:AllResults = @()

            if ($Export -match '\.(csv|json)$') {
                # Caller provided an explicit filename — use it as-is.
                $OutputPath = $Export
                $ExportFormat = ($Export -split '\.')[-1].ToUpper()
            }
            elseif ($Export -match '^(csv|json)$') {
                # Caller provided just a format keyword — auto-generate a
                # timestamped filename in the current working directory.
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

    # -- PROCESS ---------------------------------------------------------------
    # Runs once per pipeline input object (or once for a direct call).
    # All DNS queries, helper functions, and output object construction live here.
    process {
        if ($script:DnsMethod -eq 'none') {
            return $null
        }

        # -- Helper: Invoke-DnsQuery -------------------------------------------
        # Thin abstraction over Resolve-DnsName (Windows) and dig (Linux/macOS).
        # Returns a consistent array of PSCustomObjects regardless of platform,
        # each with Name, Type, TTL, and a type-specific property (IPAddress,
        # NameExchange, NameHost, or Strings).
        function Invoke-DnsQuery {
            param(
                [Parameter(Mandatory = $true)][string]$Name,
                [Parameter(Mandatory = $true)][string]$Type,
                [Parameter(Mandatory = $true)][string]$Server
            )

            if ($script:DnsMethod -eq 'ResolveDnsName') {
                return Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -ErrorAction SilentlyContinue
            }

            # -- dig path (Linux / macOS) --------------------------------------
            # +noall +answer suppresses everything except the answer section.
            $digArgs = "@$Server", "+noall", "+answer", "-t", $Type.ToUpper(), $Name
            $digOutput = & dig @digArgs 2>$null
            if (-not $digOutput) { return $null }

            $results = [System.Collections.Generic.List[object]]::new()
            foreach ($line in $digOutput) {
                # Skip blank lines and comment lines (begin with ;).
                if ([string]::IsNullOrWhiteSpace($line) -or $line -match '^\s*;') { continue }

                # Parse standard DNS answer line: name TTL IN type data
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

                    # Add a type-appropriate property to match Resolve-DnsName output shape.
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
                            # dig wraps TXT strings in quotes; extract the content.
                            # Fall back to the raw data string if no quoted parts found.
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

        # -- Helper: Get-NS ----------------------------------------------------
        # Returns a formatted string of the first two NS records with TTLs,
        # or $false if no NS records are found.
        function Get-NS {
            param (
                [Parameter(Mandatory = $true)][string]$Domain,
                [Parameter(Mandatory = $true)][string]$Server
            )

            $NS = Invoke-DnsQuery -Name $Domain -Type 'NS' -Server $Server

            if ([string]::IsNullOrWhiteSpace($NS.NameHost)) {
                return $false
            }

            $OutNS = foreach ($Item in $NS) {
                $Item | Select-Object NameHost, TTL
            }

            # Format as "ns1.example.com [TTL 3600] | ns2.example.com [TTL 3600]"
            [string]$resultsNS = ($OutNS | Select-Object -First 2 | ForEach-Object { "$($_.NameHost) [TTL $($_.TTL)]" }) -join " | "
            return $resultsNS
        }

        # -- Helper: Get-SPF ---------------------------------------------------
        # Looks up the SPF record for the domain using the specified record type.
        # TXT mode: queries TXT records directly and filters for v=spf1.
        # CNAME mode: follows a CNAME to its target, then queries TXT there.
        # Returns the SPF string, a "CNAME -> target : record" string, or $false.
        function Get-SPF {
            param (
                [Parameter(Mandatory = $true)][string]$Domain,
                [Parameter(Mandatory = $true)][string]$Server,
                [Parameter(Mandatory = $true)][string]$Type
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
                # Some providers (e.g. Proofpoint) publish SPF as a CNAME that
                # points to a TXT record rather than publishing TXT directly.
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

        # -- Domain normalisation ----------------------------------------------
        # Normalize the -Selector value to lowercase for consistent DNS lookups.
        if ($Selector -ne 'unprovided') {
            $Selector = $Selector.ToLowerInvariant()
        }

        # Parse the input into a clean hostname.
        # Try casting as a URI first (handles https://... and bare domains),
        # then as a MailAddress (handles user@domain), then fall back to raw input.
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

        if ($TestDomain) {
            try {
                # Strip any stray @ symbols, trim whitespace, and lowercase.
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

        # Unless -Sub or -JustSub is set, strip the subdomain and query only
        # the base domain (e.g. mail.example.com -> example.com).
        # Handles country-code second-level domains (e.g. co.uk, com.au) by
        # preserving three labels when the penultimate label is 2 characters.
        if (-not $Sub -and -not $JustSub) {
            $parts = $TestDomain.Split(".")
            if ($parts.Count -gt 2 -and $parts[-2].Length -eq 2 -and $parts[-1].Length -le 3) {
                $TestDomain = $parts[-3..-1] -join "."
            }
            else {
                $TestDomain = $parts[-2, -1] -join "."
            }
        }

        # Initialise DKIM result as not-found; overwritten if a record is discovered.
        $resultdkim = $false

        # Build the list of record types to iterate over.
        # Always an array so ForEach-Object receives consistent typed strings.
        # BOTH expands to two passes; TXT/CNAME produce a single-element array.
        $RecordTypeTest = @()
        if ($RecordType -eq 'BOTH') {
            $RecordTypeTest = @('TXT', 'CNAME')
        }
        else {
            $RecordTypeTest = @($RecordType.ToUpper())
        }

        # -- A record ----------------------------------------------------------
        # Boolean: $true if at least one A record resolves for the domain.
        $resultA = $null -ne (Invoke-DnsQuery -Name $TestDomain -Type 'A' -Server $Server | Where-Object { $_.Type -eq 'A' })

        # -- MX records --------------------------------------------------------
        # Sorted by preference (lowest = highest priority).
        # Non-mail subdomains legitimately have no MX; emit Verbose, not Warning.
        try {
            $mxRecords = Invoke-DnsQuery -Name $TestDomain -Type 'MX' -Server $Server |
            Sort-Object -Property Preference
        }
        catch {
            Write-Error "An error occurred while resolving DNS: $_"
            $mxRecords = $null
        }

        if ($mxRecords -and $mxRecords.Type -contains 'MX') {
            $formattedRecords = $mxRecords |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameExchange) } |
            Select-Object @{n = "Name"; e = { $_.NameExchange } },
            @{n = "Preference"; e = { $_.Preference } },
            @{n = "TTL"; e = { $_.TTL } }
            # Format as "mx1.example.com [pref 10, TTL 300] | mx2.example.com [pref 20, TTL 300]"
            $resultmx = ($formattedRecords | ForEach-Object { "$($_.Name) [pref $($_.Preference), TTL $($_.TTL)]" }) -join " | "
        }
        else {
            Write-Verbose "No MX records found for domain: $Domain"
            $resultmx = $false
        }

        # Track whether -DkimSelectors was explicitly passed so the SELECTOR
        # field can reflect the custom list when no match is found.
        $DkimExplicit = $PSBoundParameters.ContainsKey('DkimSelectors')
        # Snapshot the original selector value; $Selector may be mutated during
        # auto-discovery and needs to be restored between record-type passes.
        $SelectorHold = $Selector

        # -- Per-record-type pass ----------------------------------------------
        # For TXT or CNAME: one iteration. For BOTH: two iterations.
        # Each pass produces one output object with its own RECORDTYPE property.
        $Output = $RecordTypeTest | ForEach-Object {
            $TempType = $_

            $resultsNS = Get-NS -Domain $TestDomain -Server $Server
            $resultspf = Get-SPF -Domain $TestDomain -Server $Server -Type $TempType

            # -- DMARC ---------------------------------------------------------
            # DMARC is published at the _dmarc subdomain of the base domain.
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
                    # Follow the CNAME to its target and look for DMARC TXT there.
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

            # -- DKIM — explicit selector ---------------------------------------
            # If a selector was provided via -Selector, query that specific
            # _domainkey record and skip auto-discovery.
            if ($Selector -ne 'unprovided') {
                $DKIM = Invoke-DnsQuery -Name "$($Selector)._domainkey.$($TestDomain)" -Type $TempType -Server $Server |
                Where-Object { $_.Type -eq $TempType }

                if (-not $DKIM) {
                    $resultdkim = $false
                }
                else {
                    if ($TempType -eq 'TXT') {
                        foreach ($Item in $DKIM) {
                            if ($Item.Type -eq 'TXT' -and $Item.Strings -match "v=DKIM1") {
                                $resultdkim = ($Item.Strings -join "")
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
                                $resultdkim = "CNAME -> $targetDomain : $(($dkimRecord.Strings -join ''))"
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

            # -- DKIM — auto-discovery ------------------------------------------
            # Walk the $DkimSelectors list and stop at the first match.
            # Sets $Selector to the matched value so it appears in the output.
            if ($Selector -eq 'unprovided') {
                $BreakFlag = $false
                foreach ($line in $DkimSelectors) {
                    $DKIM = $null
                    $DKIM = Invoke-DnsQuery -Name "$($line)._domainkey.$($TestDomain)" -Type $TempType -Server $Server |
                    Where-Object { $_.Type -eq $TempType }

                    if ($TempType -eq 'TXT') {
                        $DKIM = $DKIM | Where-Object { $_.Strings -match "v=DKIM1" }
                        foreach ($Item in $DKIM) {
                            $resultdkim = ($Item.Strings -join "")
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
                                $resultdkim = "CNAME -> $targetDomain : $(($dkimRecord.Strings -join ''))"
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

            # If DKIM was not found, set the SELECTOR field to reflect what was
            # tried: the custom list (if -DkimSelectors was explicit) or the
            # original sentinel / caller-supplied value.
            if ($resultdkim -eq $false) {
                $Selector = if ($DkimExplicit) { $DkimSelectors -join ', ' } else { $SelectorHold }
            }

            # -- Output object --------------------------------------------------
            # One object per record-type pass. Property names for SPF, DMARC,
            # and DKIM include the type suffix (e.g. SPF_TXT, DMARC_CNAME)
            # so BOTH mode returns two distinguishable objects.
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

        # -- Output / accumulation ---------------------------------------------
        # JustSub: emit output for this domain only, never recurse to base domain.
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

            # Sub: after emitting the subdomain result, recurse once to query
            # the base domain. Only recurses when the input was actually a
            # subdomain (more than 2 labels). Handles ccSLD domains (co.uk etc.)
            # by preserving three labels when the penultimate is a 2-char ccSLD.
            if ($Sub -eq $true -and ($TestDomain.Split('.').count -gt 2)) {
                $tParts = $TestDomain.Split('.')
                $parentDomain = if ($tParts.Count -gt 2 -and $tParts[-2].Length -eq 2 -and $tParts[-1].Length -le 3) {
                    $tParts[-3..-1] -join '.'
                }
                else {
                    $tParts[-2, -1] -join '.'
                }
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

    # -- END -------------------------------------------------------------------
    # Runs once after all pipeline input has been processed.
    # Writes the accumulated results to CSV or JSON if -Export was specified.
    end {
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
