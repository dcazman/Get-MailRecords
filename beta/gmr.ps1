<#
.SYNOPSIS
v2.0.0 — Queries mail DNS records (MX, SPF, DKIM, DMARC, BIMI, etc.) for a domain or email.

.DESCRIPTION
Performs a comprehensive audit of mail-related DNS records. Includes FCrDNS (Forward-Confirmed
Reverse DNS) validation and DKIM selector auto-discovery.

By default, subdomains are stripped to the base domain (mail.example.com → example.com).
Use -Sub to check both, or -JustSub to check only the subdomain as given.

.PARAMETER Domain
The target domain, email address, or URL. Alias: -d

.PARAMETER Sub
Check both the provided subdomain and the base domain. Alias: -s

.PARAMETER JustSub
Check only the domain exactly as provided; skips base domain extraction. Alias: -js

.PARAMETER Selector
Explicit DKIM selector. If omitted, common selectors are tried automatically. Alias: -sel

.PARAMETER DkimSelectors
List of DKIM selectors to try when no explicit -Selector is provided. Alias: -dkim

.PARAMETER RecordType
Type to query (TXT, CNAME, or BOTH). Default: TXT. Alias: -r

.PARAMETER Server
DNS server to query. Default: 8.8.8.8. Alias: -srv

.PARAMETER Export
Export to 'CSV' or 'JSON'. Provide a filename or just the format. Alias: -e

.EXAMPLE
Get-MailRecords -Domain example.com
Basic lookup for a single domain.

.EXAMPLE
GMR -d mail.example.com -Sub -Export results.csv
Queries subdomain + base domain and saves to a CSV file.

.EXAMPLE
"google.com", "microsoft.com" | Get-MailRecords -r BOTH
Pipes multiple domains and checks both TXT and CNAME records.

.LINK
https://github.com/dcazman/Get-MailRecords

.NOTES
Author: Dan Casmas | gmr.thecasmas.com
Requires Resolve-DnsName (Windows) or dig (Linux/macOS).
PTR performs an FCrDNS check: '===' (Match) or '=/=' (Mismatch).
#>
function Get-MailRecords {
    [Alias("GMR")]
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [alias('d')]
        [string]$Domain,

        [parameter(Mandatory = $false)]
        [alias('s')]
        [switch]$Sub,

        [parameter(Mandatory = $false)]
        [alias('js')]
        [switch]$JustSub,

        [parameter(Mandatory = $false)]
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
        [alias('r')]
        [string]$RecordType = 'TXT',

        [parameter(Mandatory = $false)]
        [alias('srv')]
        [string]$Server = '8.8.8.8',

        [parameter(Mandatory = $false)]
        [alias('e')]
        [string]$Export
    )

    begin {
        $script:DnsMethod = if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) { 'ResolveDnsName' }
        elseif (Get-Command dig -ErrorAction SilentlyContinue) { 'dig' }
        else { 'none' }

        if ($script:DnsMethod -eq 'none') { throw "Neither Resolve-DnsName nor dig found." }

        $script:AllResults = @()
        $ExportFormat = $null
        $OutputPath = $null

        if ($Export) {
            if ($Export -match '\.(csv|json)$') {
                $OutputPath = $Export
                $ExportFormat = ($Export -split '\.')[-1].ToUpper()
            }
            elseif ($Export -match '^(csv|json)$') {
                $ExportFormat = $Export.ToUpper()
                $OutputPath = Join-Path (Get-Location).Path "MailRecords_$((Get-Date -f 'yyyyMMdd_HHmm')).$($Export.ToLower())"
            }
            else {
                Write-Warning "Invalid -Export value '$Export'. Use 'CSV', 'JSON', or a filename ending in .csv/.json."
            }
        }

        function Invoke-DnsQuery {
            param([string]$Name, [string]$Type, [string]$Server)
            if ($Type -eq 'BOTH') { $Type = 'TXT' }

            if ($script:DnsMethod -eq 'ResolveDnsName') {
                return Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -ErrorAction SilentlyContinue
            }
            $digOutput = & dig "@$Server" "+noall" "+answer" "-t" $Type.ToUpper() $Name 2>$null
            $res = [System.Collections.Generic.List[object]]::new()
            foreach ($line in $digOutput) {
                if ($line -match '^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$') {
                    $obj = [PSCustomObject]@{ Name = $Matches[1].TrimEnd('.'); Type = $Matches[3].ToUpper(); TTL = [int]$Matches[2] }
                    switch ($obj.Type) {
                        'A' { $obj | Add-Member 'IPAddress' $Matches[4].Trim() }
                        'MX' { if ($Matches[4] -match '^(\d+)\s+(\S+)$') { $obj | Add-Member 'Preference' ([int]$Matches[1]); $obj | Add-Member 'NameExchange' $Matches[2].TrimEnd('.') } }
                        { $_ -in 'NS', 'CNAME' } { $obj | Add-Member 'NameHost' $Matches[4].Trim().TrimEnd('.') }
                        'TXT' {
                            $parts = [regex]::Matches($Matches[4], '"([^"]*)"|(\S+)') | ForEach-Object { if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value } }
                            $obj | Add-Member 'Strings' @($parts)
                        }
                    }
                    $res.Add($obj)
                }
            }
            return $res.ToArray()
        }

        function Get-PTR {
            param($IP, $Srv)
            if ($IP -eq 'None') { return @{ Host = 'None'; Status = 'None' } }
            if ($script:DnsMethod -eq 'ResolveDnsName') {
                $ptr = Resolve-DnsName $IP -Type PTR -Server $Srv -ErrorAction SilentlyContinue | Select-Object -First 1
                $hostName = $ptr.NameHost
            }
            else {
                $hostName = (& dig "@$Srv" "+short" "-x" $IP)[0]?.TrimEnd('.')
            }
            if (-not $hostName) { return @{ Host = 'None'; Status = 'None' } }
            $fwd = Invoke-DnsQuery -Name $hostName -Type 'A' -Server $Srv
            $status = if ($fwd.IPAddress -contains $IP) { '===' } else { '=/=' }
            return @{ Host = $hostName; Status = $status }
        }
    }

    process {
        $CleanDomain = $Domain -replace '^https?://', '' -replace '^www\.', '' -replace '^.*@', ''
        $CleanDomain = $CleanDomain.Split('/')[0].ToLowerInvariant().Trim()

        # Determine base domain (heuristic ccTLD detection for e.g. co.uk)
        $p = $CleanDomain.Split('.')
        $baseDomain = if ($p.Count -gt 2 -and $p[-2].Length -eq 2 -and $p[-1].Length -le 3) { $p[-3..-1] -join '.' } else { $p[-2, -1] -join '.' }
        $isSubdomain = $baseDomain -ne $CleanDomain

        # Default: strip to base domain. -Sub: check both. -JustSub: check only what was passed.
        $Queue = if ($JustSub) {
            @($CleanDomain)
        } elseif ($Sub) {
            if ($isSubdomain) { @($CleanDomain, $baseDomain) } else { @($CleanDomain) }
        } else {
            @($baseDomain)
        }

        foreach ($Target in $Queue) {
            # Normalize to uppercase so field names (SPF_TXT, SPF_CNAME) are consistent regardless of input case
            $RecordTypes = if ($RecordType -ieq 'BOTH') { @('TXT', 'CNAME') } else { @($RecordType.ToUpper()) }

            # Per-domain lookups — done once, not repeated per RecordType.
            # Filter by Type to drop CNAME records Resolve-DnsName returns when following chains.
            $mx  = Invoke-DnsQuery -Name $Target -Type 'MX' -Server $Server |
                   Where-Object { $_.Type -eq 'MX' } | Sort-Object Preference
            $mxA = if ($mx -and $mx[0].NameExchange) {
                       (Invoke-DnsQuery -Name $mx[0].NameExchange -Type 'A' -Server $Server |
                        Select-Object -ExpandProperty IPAddress -First 1) ?? 'None'
                   } else { 'None' }
            $ptr = Get-PTR -IP $mxA -Srv $Server
            $ptrDisplay = if ($mxA -ne 'None') { "$($ptr.Host) $($ptr.Status) $mxA" } else { 'None' }

            $nsItems = Invoke-DnsQuery -Name $Target -Type 'NS' -Server $Server |
                       Where-Object { $_.Type -eq 'NS' } | Select-Object -First 2
            $ns = if ($nsItems) { ($nsItems | ForEach-Object { "$($_.NameHost) [TTL $($_.TTL)]" }) -join " | " } else { 'None' }

            # TXT-only records — queried once per domain regardless of -RecordType
            $bimiRaw   = Invoke-DnsQuery "default._bimi.$Target" 'TXT' $Server
            $mtaStsRaw = Invoke-DnsQuery "_mta-sts.$Target" 'TXT' $Server
            $tlsRptRaw = Invoke-DnsQuery "_smtp._tls.$Target" 'TXT' $Server
            $bimi   = if ($bimiRaw)   { ($bimiRaw.Strings   -like "v=BIMI1*"    | Select-Object -First 1) ?? 'None' } else { 'None' }
            $mtaSts = if ($mtaStsRaw) { ($mtaStsRaw.Strings -like "v=STSv1*"    | Select-Object -First 1) ?? 'None' } else { 'None' }
            $tlsRpt = if ($tlsRptRaw) { ($tlsRptRaw.Strings -like "v=TLSRPTv1*" | Select-Object -First 1) ?? 'None' } else { 'None' }

            foreach ($RT in $RecordTypes) {
                # SPF
                $spfRaw    = Invoke-DnsQuery -Name $Target -Type $RT -Server $Server
                $spfResult = if ($RT -eq 'TXT') {
                    ($spfRaw.Strings | Where-Object { $_ -like "v=spf1*" })
                } else {
                    $cname = $spfRaw | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                    if ($cname) { (Invoke-DnsQuery -Name $cname.NameHost -Type 'TXT' -Server $Server).Strings | Where-Object { $_ -like "v=spf1*" } }
                }

                # DMARC
                $dmRaw    = Invoke-DnsQuery -Name "_dmarc.$Target" -Type $RT -Server $Server
                $dmResult = if ($RT -eq 'TXT') {
                    ($dmRaw.Strings | Where-Object { $_ -like "v=DMARC1*" })
                } else {
                    $cname = $dmRaw | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                    if ($cname) { (Invoke-DnsQuery -Name $cname.NameHost -Type 'TXT' -Server $Server).Strings | Where-Object { $_ -like "v=DMARC1*" } }
                }

                # DKIM
                $dkimResult = 'None'; $finalSel = 'unprovided'
                $selectorsToTry = if ($Selector) { @($Selector) } else { $DkimSelectors }
                foreach ($s in $selectorsToTry) {
                    $dk = Invoke-DnsQuery -Name "$s._domainkey.$Target" -Type $RT -Server $Server
                    if ($dk) {
                        if ($RT -eq 'TXT') {
                            $dkimRec = $dk | Where-Object { $_.Strings -match "v=DKIM1" } | Select-Object -First 1
                            if ($dkimRec) { $dkimResult = $dkimRec.Strings -join ""; $finalSel = $s; break }
                        } else {
                            $cname = $dk | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                            if ($cname) {
                                $dkimRec = (Invoke-DnsQuery -Name $cname.NameHost -Type 'TXT' -Server $Server) | Where-Object { $_.Strings -match "v=DKIM1" } | Select-Object -First 1
                                if ($dkimRec) { $dkimResult = $dkimRec.Strings -join ""; $finalSel = $s; break }
                            }
                        }
                    }
                }

                $out = [PSCustomObject]@{
                    DOMAIN      = $Target
                    SERVER      = $Server
                    RECORDTYPE  = $RT
                    MX_A        = $mxA
                    PTR         = $ptrDisplay
                    MX          = if ($mx) { ($mx | ForEach-Object { "$($_.NameExchange) [pref $($_.Preference)]" }) -join " | " } else { 'None' }
                    "SPF_$RT"   = $spfResult ?? 'None'
                    "DMARC_$RT" = $dmResult ?? 'None'
                    "DKIM_$RT"  = $dkimResult
                    SELECTOR    = $finalSel
                    BIMI        = $bimi
                    NS_First2   = $ns
                    MTA_STS     = $mtaSts
                    TLS_RPT     = $tlsRpt
                }

                if ($ExportFormat) { $script:AllResults += $out } else { $out }
            }
        }
    }

    end {
        if ($ExportFormat -and $script:AllResults.Count -gt 0) {
            if ($ExportFormat -eq 'CSV') { $script:AllResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force }
            else { $script:AllResults | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Force }
            Write-Host "Results exported to: $OutputPath" -F Green
        }
    }
}
