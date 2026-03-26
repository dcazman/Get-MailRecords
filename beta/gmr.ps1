<#
.SYNOPSIS
Performs DNS lookups (A, PTR, MX, SPF, DMARC, DKIM, BIMI, NS, MTA-STS, TLS-RPT) for a domain, email, or URL.
.DESCRIPTION
Checks for common mail-related DNS records on a given domain, email address, or URL.
Supports record types TXT, CNAME, or BOTH for SPF, DMARC, and DKIM.
If a DKIM selector is not provided, common selectors are tried automatically.
Function alias: GMR. Parameter aliases: -d (Domain), -s (Sub), -js (JustSub), -sel (Selector), -dkim (DkimSelectors), -r (RecordType), -srv (Server), -e (Export).
.PARAMETER Domain
The full domain name, email address, or URL to query. Mandatory. Alias: -d
.PARAMETER Sub
Query both the subdomain and the base domain. Alias: -s
.PARAMETER JustSub
Query only the subdomain, skip the base domain lookup. Alias: -js
.PARAMETER Selector
Explicit DKIM selector to query. If not provided, selectors in -DkimSelectors are tried automatically. Alias: -sel
.PARAMETER DkimSelectors
List of DKIM selectors to try when no -Selector is given. Alias: -dkim
.PARAMETER RecordType
Record type to query for SPF, DMARC, and DKIM. Valid options: 'TXT', 'CNAME', 'BOTH'. Default: 'TXT'. Alias: -r
.PARAMETER Server
DNS server to query. Default: 8.8.8.8. Alias: -srv
.PARAMETER Export
Export results to file. Provide a filename (e.g., 'results.csv', 'output.json') or just the format ('CSV', 'JSON'). Alias: -e
.EXAMPLE
Get-MailRecords -Domain example.com
GMR -d example.com
.EXAMPLE
Get-MailRecords -Domain mail.example.com -Sub
GMR -d mail.example.com -s
.EXAMPLE
Get-MailRecords -Domain mail.example.com -JustSub
GMR -d mail.example.com -js
.EXAMPLE
Get-MailRecords -Domain example.com -Selector selector1
GMR -d example.com -sel selector1
.EXAMPLE
Get-MailRecords -Domain example.com -Server 1.1.1.1
GMR -d example.com -srv 1.1.1.1
.EXAMPLE
Get-MailRecords -Domain example.com -RecordType CNAME
GMR -d example.com -r CNAME
.EXAMPLE
Get-MailRecords -Domain example.com -Export results.csv
GMR -d example.com -e results.csv
.EXAMPLE
"google.com", "microsoft.com" | Get-MailRecords -Export output.json
.LINK
https://github.com/dcazman/Get-MailRecords
.NOTES
Author: Dan Casmas
Tested on Windows PowerShell 5.1 and PowerShell 7 (Windows, Linux, macOS).
Minimum required version: 5.1.
Requires Resolve-DnsName (Windows built-in) or dig (Linux/macOS: install bind-utils or dnsutils).
Function alias: GMR.
Only the first two NS results are returned (NS_First2).
CNAME record types will follow the CNAME chain to retrieve the final TXT record value.
Try it now - no install required: gmr.thecasmas.com
Portions of code adapted from Jordan W.
#>
function Get-MailRecords {
    [Alias("GMR")]
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, HelpMessage = "Enter the full domain name, email address, or URL.", Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
                if ($_ -like "*.*") { return $true }
                else { throw [System.Management.Automation.ValidationMetadataException] "Enter the full domain name, email address, or URL." }
            })]
        [alias('d')]
        [string]$Domain,

        [parameter(Mandatory = $false)]
        [alias('s')]
        [switch]$Sub,

        [parameter(Mandatory = $false)]
        [alias('js')]
        [switch]$JustSub,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [alias('sel')]
        [string]$Selector,

        [parameter(Mandatory = $false)]
        [alias('dkim')]
        [string[]]$DkimSelectors = @(
            "default", "s", "s1", "s2", "selector1", "selector2", "pps1", "google",
            "everlytickey1", "everlytickey2", "eversrv", "k1", "mxvault", "dkim",
            "mail", "s1024", "s2048", "s4096"
        ),

        [parameter(Mandatory = $false)]
        [ValidateSet('TXT', 'CNAME', 'BOTH')]
        [ValidateNotNullOrEmpty()]
        [alias('r')]
        [string]$RecordType = 'TXT',

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [alias('srv')]
        [string]$Server = '8.8.8.8',

        [parameter(Mandatory = $false)]
        [alias('e')]
        [string]$Export
    )

    # -- BEGIN -----------------------------------------------------------------
    begin {
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
            $script:AllResults = @()
            if ($Export -match '\.(csv|json)$') {
                $OutputPath = $Export
                $ExportFormat = ($Export -split '\.')[-1].ToUpper()
            }
            elseif ($Export -match '^(csv|json)$') {
                $ExportFormat = $Export.ToUpper()
                $timestamp = Get-Date -Format "yyyyMMdd_HHmm"
                $extension = $ExportFormat.ToLower()
                $OutputPath = Join-Path (Get-Location).Path "MailRecords_$timestamp.$extension"
            }
            else {
                Write-Error "Export parameter must be a filename with .csv/.json extension, or 'CSV'/'JSON'."
                return
            }
        }
    }

    # -- PROCESS ---------------------------------------------------------------
    process {
        if ($script:DnsMethod -eq 'none') { return $null }

        # -- Helper: Invoke-DnsQuery -------------------------------------------
        function Invoke-DnsQuery {
            param(
                [Parameter(Mandatory = $true)][string]$Name,
                [Parameter(Mandatory = $true)][string]$Type,
                [Parameter(Mandatory = $true)][string]$Server
            )
            if ($script:DnsMethod -eq 'ResolveDnsName') {
                return Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -ErrorAction SilentlyContinue
            }
            $digArgs = "@$Server", "+noall", "+answer", "-t", $Type.ToUpper(), $Name
            $digOutput = & dig @digArgs 2>$null
            if (-not $digOutput) { return $null }
            $results = [System.Collections.Generic.List[object]]::new()
            foreach ($line in $digOutput) {
                if ([string]::IsNullOrWhiteSpace($line) -or $line -match '^\s*;') { continue }
                if ($line -match '^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$') {
                    $recordName = $Matches[1].TrimEnd('.')
                    $ttl = [int]$Matches[2]
                    $recordType = $Matches[3].ToUpper()
                    $data = $Matches[4].Trim()
                    $obj = [PSCustomObject]@{ Name = $recordName; Type = $recordType; TTL = $ttl }
                    switch ($recordType) {
                        'A' { $obj | Add-Member -NotePropertyName 'IPAddress' -NotePropertyValue $data }
                        'MX' {
                            if ($data -match '^(\d+)\s+(\S+)$') {
                                $obj | Add-Member -NotePropertyName 'Preference'    -NotePropertyValue ([int]$Matches[1])
                                $obj | Add-Member -NotePropertyName 'NameExchange'  -NotePropertyValue $Matches[2].TrimEnd('.')
                            }
                        }
                        'NS' { $obj | Add-Member -NotePropertyName 'NameHost' -NotePropertyValue $data.TrimEnd('.') }
                        'CNAME' { $obj | Add-Member -NotePropertyName 'NameHost' -NotePropertyValue $data.TrimEnd('.') }
                        'PTR' { $obj | Add-Member -NotePropertyName 'NameHost' -NotePropertyValue $data.TrimEnd('.') }
                        'TXT' {
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
        function Get-NS {
            param ([string]$Domain, [string]$Server)
            $NS = Invoke-DnsQuery -Name $Domain -Type 'NS' -Server $Server
            if (-not $NS -or [string]::IsNullOrWhiteSpace($NS.NameHost)) { return 'None' }
            $OutNS = foreach ($Item in $NS) { $Item | Select-Object NameHost, TTL }
            return ($OutNS | Select-Object -First 2 | ForEach-Object { "$($_.NameHost) [TTL $($_.TTL)]" }) -join " | "
        }

        # -- Helper: Get-SPF ---------------------------------------------------
        function Get-SPF {
            param ([string]$Domain, [string]$Server, [string]$Type)
            $SPF = Invoke-DnsQuery -Name $Domain -Type $Type -Server $Server
            if ($Type -eq 'TXT') {
                $spfRecord = $SPF.Strings | Where-Object { $_ -like "v=spf1*" }
                if ([string]::IsNullOrWhiteSpace($spfRecord)) { return 'None' }
                return $spfRecord
            }
            elseif ($Type -eq 'CNAME') {
                $cnameRecord = $SPF | Where-Object { $_.Type -eq 'CNAME' }
                if ($cnameRecord) {
                    $targetDomain = $cnameRecord.NameHost
                    $targetSPF = Invoke-DnsQuery -Name $targetDomain -Type 'TXT' -Server $Server
                    $spfRecord = $targetSPF.Strings | Where-Object { $_ -like "v=spf1*" }
                    if ($spfRecord) { return "CNAME -> $targetDomain : $spfRecord" }
                    return "CNAME -> $targetDomain (no SPF found)"
                }
                return 'None'
            }
        }

        # -- Helper: Get-PTR ---------------------------------------------------
        # Takes an IP address, performs reverse DNS lookup, returns hostname and match status.
        function Get-PTR {
            param ([string]$IP, [string]$Server)
            if ($IP -eq 'None' -or [string]::IsNullOrWhiteSpace($IP)) { return @{ Host = 'None'; Status = 'None' } }

            $ptrResult = $null
            if ($script:DnsMethod -eq 'ResolveDnsName') {
                $ptrResult = Resolve-DnsName -Name $IP -Type PTR -Server $Server -DnsOnly -ErrorAction SilentlyContinue |
                Where-Object { $_.Type -eq 'PTR' } |
                Select-Object -First 1
                $ptrHost = $ptrResult.NameHost
            }
            else {
                $digArgs = "@$Server", "+noall", "+answer", "-x", $IP
                $digOutput = & dig @digArgs 2>$null
                $ptrHost = $null
                foreach ($line in $digOutput) {
                    if ($line -match 'PTR\s+(\S+)$') {
                        $ptrHost = $Matches[1].TrimEnd('.')
                        break
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($ptrHost)) {
                return @{ Host = 'None'; Status = 'None' }
            }

            # FCrDNS check: forward-resolve the PTR hostname and confirm the original IP is present.
            $fwdQuery = Invoke-DnsQuery -Name $ptrHost -Type 'A' -Server $Server | Where-Object { $_.Type -eq 'A' }
            $fwdIPs = $fwdQuery | ForEach-Object { $_.IPAddress }
            $status = if ($fwdIPs -contains $IP) { '===' } else { '=/=' }
            return @{ Host = $ptrHost; Status = $status }
        }

        # -- Helper: Get-BIMI --------------------------------------------------
        # BIMI published at default._bimi.<domain> as a TXT record.
        function Get-BIMI {
            param ([string]$Domain, [string]$Server)
            $bimi = Invoke-DnsQuery -Name "default._bimi.$Domain" -Type 'TXT' -Server $Server
            $bimiRecord = $bimi.Strings | Where-Object { $_ -like "v=BIMI1*" }
            if ([string]::IsNullOrWhiteSpace($bimiRecord)) { return 'None' }
            return $bimiRecord
        }

        # -- Helper: Get-MTASTS ------------------------------------------------
        # MTA-STS policy signal at _mta-sts.<domain> as a TXT record.
        function Get-MTASTS {
            param ([string]$Domain, [string]$Server)
            $mta = Invoke-DnsQuery -Name "_mta-sts.$Domain" -Type 'TXT' -Server $Server
            $mtaRecord = $mta.Strings | Where-Object { $_ -like "v=STSv1*" }
            if ([string]::IsNullOrWhiteSpace($mtaRecord)) { return 'None' }
            return $mtaRecord
        }

        # -- Helper: Get-TLSRPT ------------------------------------------------
        # TLS reporting at _smtp._tls.<domain> as a TXT record.
        function Get-TLSRPT {
            param ([string]$Domain, [string]$Server)
            $tls = Invoke-DnsQuery -Name "_smtp._tls.$Domain" -Type 'TXT' -Server $Server
            $tlsRecord = $tls.Strings | Where-Object { $_ -like "v=TLSRPTv1*" }
            if ([string]::IsNullOrWhiteSpace($tlsRecord)) { return 'None' }
            return $tlsRecord
        }

        # -- Domain normalisation ----------------------------------------------
        $UserProvidedSelector = $PSBoundParameters.ContainsKey('Selector')
        $SelectorInput = if ($UserProvidedSelector) { $Selector.ToLowerInvariant() } else { $null }

        $TestDomain = try { ([System.Uri]$Domain).Host.TrimStart('www.') }
        catch {
            try { ([Net.Mail.MailAddress]$Domain).Host }
            catch { $Domain }
        }

        if ($TestDomain) {
            try { $TestDomain = $TestDomain.Replace('@', '').Trim().ToLowerInvariant() }
            catch { Write-Error "Problem with $Domain as entered."; return $null }
        }
        else {
            Write-Error "Problem with $Domain as entered."
            return $null
        }

        if (-not $Sub -and -not $JustSub) {
            $parts = $TestDomain.Split(".")
            if ($parts.Count -gt 2 -and $parts[-2].Length -eq 2 -and $parts[-1].Length -le 3) {
                $TestDomain = $parts[-3..-1] -join "."
            }
            else {
                $TestDomain = $parts[-2, -1] -join "."
            }
        }

        # -- Record type iteration setup ---------------------------------------
        $RecordTypeTest = if ($RecordType -eq 'BOTH') { @('TXT', 'CNAME') } else { @($RecordType.ToUpper()) }

        # -- MX records --------------------------------------------------------
        try {
            $mxRecords = Invoke-DnsQuery -Name $TestDomain -Type 'MX' -Server $Server | Sort-Object -Property Preference
        }
        catch {
            Write-Error "An error occurred while resolving MX: $_"
            $mxRecords = $null
        }

        $primaryMxHost = $null
        if ($mxRecords -and $mxRecords.Type -contains 'MX') {
            $formattedMX = $mxRecords |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameExchange) } |
            Select-Object @{n = "Name"; e = { $_.NameExchange } }, @{n = "Preference"; e = { $_.Preference } }, @{n = "TTL"; e = { $_.TTL } }
            $resultmx = ($formattedMX | ForEach-Object { "$($_.Name) [pref $($_.Preference), TTL $($_.TTL)]" }) -join " | "
            $primaryMxHost = ($mxRecords | Where-Object { -not [string]::IsNullOrWhiteSpace($_.NameExchange) } | Select-Object -First 1).NameExchange
        }
        else {
            Write-Verbose "No MX records found for domain: $Domain"
            $resultmx = 'None'
        }

        # -- A record (primary MX host) ----------------------------------------
        # Resolves the lowest-preference MX hostname to an IP — this is the IP
        # that matters for PTR/mail-server identity checks.
        if ($primaryMxHost) {
            $aQuery = Invoke-DnsQuery -Name $primaryMxHost -Type 'A' -Server $Server | Where-Object { $_.Type -eq 'A' }
            $resultA = if ($aQuery) { ($aQuery | Select-Object -First 1).IPAddress } else { 'None' }
        }
        else {
            $resultA = 'None'
        }

        # -- PTR record --------------------------------------------------------
        $ptrData = Get-PTR -IP $resultA -Server $Server
        $resultPTR = if ($ptrData.Host -ne 'None') { "$($ptrData.Host) $($ptrData.Status) $resultA" } else { 'None' }

        # -- Per-record-type pass ----------------------------------------------
        $Output = $RecordTypeTest | ForEach-Object {
            $TempType = $_

            # Reset DKIM state for each pass
            $resultdkim = 'None'
            $SelectorOut = 'unprovided'

            # -- SPF -----------------------------------------------------------
            $resultspf = Get-SPF -Domain $TestDomain -Server $Server -Type $TempType

            # -- DMARC ---------------------------------------------------------
            $DMARC = Invoke-DnsQuery -Name "_dmarc.$TestDomain" -Type $TempType -Server $Server
            if (-not $DMARC) {
                $resultdmarc = 'None'
            }
            else {
                if ($TempType -eq 'TXT') {
                    $dm = ($DMARC.Strings -like "v=DMARC1*") -join ' '
                    $resultdmarc = if ([string]::IsNullOrWhiteSpace($dm)) { 'None' } else { $dm }
                }
                elseif ($TempType -eq 'CNAME') {
                    $cnameRecord = $DMARC | Where-Object { $_.Type -eq 'CNAME' }
                    if ($cnameRecord) {
                        $targetDomain = $cnameRecord.NameHost
                        $targetDMARC = Invoke-DnsQuery -Name $targetDomain -Type 'TXT' -Server $Server
                        $dmarcRecord = ($targetDMARC.Strings -like "v=DMARC1*") -join ' '
                        $resultdmarc = if ($dmarcRecord) { "CNAME -> $targetDomain : $dmarcRecord" } else { "CNAME -> $targetDomain (no DMARC found)" }
                    }
                    else { $resultdmarc = 'None' }
                }
            }

            # -- DKIM ----------------------------------------------------------
            if ($UserProvidedSelector) {
                # User provided a selector — query it directly, no auto-discovery.
                $SelectorOut = $SelectorInput
                $DKIM = Invoke-DnsQuery -Name "$($SelectorInput)._domainkey.$($TestDomain)" -Type $TempType -Server $Server |
                Where-Object { $_.Type -eq $TempType }
                if ($DKIM) {
                    if ($TempType -eq 'TXT') {
                        foreach ($Item in $DKIM) {
                            if ($Item.Strings -match "v=DKIM1") {
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
                            $resultdkim = if ($dkimRecord) { "CNAME -> $targetDomain : $(($dkimRecord.Strings -join ''))" } else { 'None' }
                        }
                    }
                }
            }
            else {
                # No selector provided — run auto-discovery.
                $BreakFlag = $false
                foreach ($line in $DkimSelectors) {
                    $DKIM = Invoke-DnsQuery -Name "$($line)._domainkey.$($TestDomain)" -Type $TempType -Server $Server |
                    Where-Object { $_.Type -eq $TempType }
                    if ($TempType -eq 'TXT') {
                        $DKIM = $DKIM | Where-Object { $_.Strings -match "v=DKIM1" }
                        foreach ($Item in $DKIM) {
                            $resultdkim = ($Item.Strings -join "")
                            $SelectorOut = $line
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
                                $SelectorOut = $line
                                $BreakFlag = $true
                            }
                        }
                    }
                    if ($BreakFlag) { break }
                }
                # SelectorOut stays 'unprovided' if nothing was found
            }

            # -- BIMI ----------------------------------------------------------
            $resultBIMI = Get-BIMI -Domain $TestDomain -Server $Server

            # -- NS ------------------------------------------------------------
            $resultsNS = Get-NS -Domain $TestDomain -Server $Server

            # -- MTA-STS -------------------------------------------------------
            $resultMTASTS = Get-MTASTS -Domain $TestDomain -Server $Server

            # -- TLS-RPT -------------------------------------------------------
            $resultTLSRPT = Get-TLSRPT -Domain $TestDomain -Server $Server

            # -- Output object -------------------------------------------------
            [PSCustomObject]@{
                DOMAIN            = $TestDomain
                SERVER            = $Server
                RECORDTYPE        = $TempType
                MX_A              = $resultA
                PTR               = $resultPTR
                MX                = $resultmx
                "SPF_$TempType"   = $resultspf
                "DMARC_$TempType" = $resultdmarc
                "DKIM_$TempType"  = $resultdkim
                SELECTOR          = $SelectorOut
                BIMI              = $resultBIMI
                NS_First2         = $resultsNS
                MTA_STS           = $resultMTASTS
                TLS_RPT           = $resultTLSRPT
            }
        }

        # -- Output / accumulation ---------------------------------------------
        if ($JustSub) {
            if ($Export) { $script:AllResults += $Output } else { return $Output }
        }
        else {
            if ($Export) { $script:AllResults += $Output } else { $Output }
            if ($Sub -eq $true -and ($TestDomain.Split('.').count -gt 2)) {
                $tParts = $TestDomain.Split('.')
                $parentDomain = if ($tParts.Count -gt 2 -and $tParts[-2].Length -eq 2 -and $tParts[-1].Length -le 3) {
                    $tParts[-3..-1] -join '.'
                }
                else {
                    $tParts[-2, -1] -join '.'
                }
                if ($parentDomain -ne $TestDomain) {
                    $subParams = @{ Domain = $parentDomain; Server = $Server; RecordType = $RecordType }
                    if ($UserProvidedSelector) { $subParams['Selector'] = $SelectorInput }
                    $subOutput = Get-MailRecords @subParams
                    if ($Export) { $script:AllResults += $subOutput } else { $subOutput }
                }
            }
        }
    }

    # -- END -------------------------------------------------------------------
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
            catch { Write-Error "Failed to export results: $_" }
        }
    }
}
