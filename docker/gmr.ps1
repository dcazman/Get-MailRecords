<#
.SYNOPSIS
v2.0.0 — Queries mail DNS records (MX, SPF, DKIM, DMARC, BIMI, NS, MTA and TLS) for a domain or email.

.DESCRIPTION
Performs a comprehensive audit of mail-related DNS records. Includes FCrDNS (Forward-Confirmed
Reverse DNS) validation and DKIM selector auto-discovery.

By default, subdomains are stripped to the base domain (mail.example.com ? example.com).
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
Type to query (TXT, CNAME, or BOTH). Default: TXT. Alias: -rt, -r

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
        [Parameter(Mandatory = $true, HelpMessage = "Enter the full domain name, email address, or URL.", ValueFromPipeline = $true, Position = 0)]
        [Alias('d')]
        [string]$Domain,

        [Parameter(HelpMessage = "Also check the base domain when a subdomain is provided.")]
        [Alias('s')]
        [switch]$Sub,

        [Parameter(HelpMessage = "Check only the domain exactly as provided; skip base domain extraction.")]
        [Alias('js')]
        [switch]$JustSub,

        [Parameter(HelpMessage = "Explicit DKIM selector to query. If omitted, common selectors are tried automatically.")]
        [Alias('sel')]
        [string]$Selector,

        [Parameter(HelpMessage = "List of DKIM selectors to try when no explicit -Selector is provided.")]
        [Alias('dkim')]
        [string[]]$DkimSelectors = @(
            "default", "s", "s1", "s2", "selector1", "selector2", "pps1", "google",
            "everlytickey1", "everlytickey2", "eversrv", "k1", "mxvault", "dkim",
            "mail", "s1024", "s2048", "s4096"
        ),

        [Parameter(HelpMessage = "DNS record type to query: TXT, CNAME, or BOTH. Default: TXT.")]
        [ValidateSet('TXT', 'CNAME', 'BOTH')]
        [Alias('rt', 'r')]
        [string]$RecordType = 'TXT',

        [Parameter(HelpMessage = "DNS server to query. Default: 8.8.8.8.")]
        [Alias('srv')]
        [string]$Server = '8.8.8.8',

        [Parameter(HelpMessage = "Export results to CSV or JSON. Provide a filename (e.g. results.csv) or just the format (csv or json).")]
        [Alias('e')]
        [string]$Export
    )

    begin {
        # DNS method detection
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $script:DnsMethod = 'ResolveDnsName'
        }
        elseif (Get-Command dig -ErrorAction SilentlyContinue) {
            $script:DnsMethod = 'dig'
        }
        else {
            throw "Neither Resolve-DnsName nor dig found."
        }

        $script:AllResults = [System.Collections.Generic.List[object]]::new()

        function Get-TxtValue($name, $pattern) {
            $raw = Invoke-DnsQuery $name 'TXT' $Server
            if (-not $raw) { return 'None' }

            $val = $raw | ForEach-Object { $_.Strings } | Where-Object { $_ -like $pattern } | Select-Object -First 1
            return $val ?? 'None'
        }

        # Export handling
        $ExportFormat = $null
        $OutputPath = $null

        if ($Export) {
            if ($Export -match '\.(csv|json)$') {
                $OutputPath = $Export
                $ExportFormat = ($Export -split '\.')[-1].ToUpper()
            }
            elseif ($Export -match '^(csv|json)$') {
                $ExportFormat = $Export.ToUpper()
                $OutputPath = Join-Path (Get-Location).Path ("MailRecords_{0}.{1}" -f (Get-Date -Format 'yyyyMMdd_HHmm'), $Export.ToLower())
            }
            else {
                Write-Warning "Invalid -Export value '$Export'."
            }
        }

        function Invoke-DnsQuery {
            param(
                [string]$Name,
                [string]$Type,
                [string]$Server
            )

            if ($Type -eq 'BOTH') {
                return @('TXT', 'CNAME') | ForEach-Object { Invoke-DnsQuery -Name $Name -Type $_ -Server $Server }
            }

            if ($script:DnsMethod -eq 'ResolveDnsName') {
                return Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -ErrorAction SilentlyContinue
            }

            $output = & dig "@$Server" "+noall" "+answer" "+time=2" "+tries=1" "-t" $Type.ToUpper() $Name 2>$null
            $results = [System.Collections.Generic.List[object]]::new()

            foreach ($line in $output) {
                if ($line -match '^(\S+)\s+(\d+)\s+IN\s+(\S+)\s+(.+)$') {
                    $obj = [PSCustomObject]@{
                        Name = $Matches[1].TrimEnd('.')
                        Type = $Matches[3].ToUpper()
                        TTL  = [int]$Matches[2]
                    }

                    switch ($obj.Type) {
                        'A' {
                            $obj | Add-Member -NotePropertyName IPAddress -NotePropertyValue $Matches[4].Trim()
                        }
                        'MX' {
                            if ($Matches[4] -match '^(\d+)\s+(\S+)$') {
                                $obj | Add-Member Preference ([int]$Matches[1])
                                $obj | Add-Member NameExchange $Matches[2].TrimEnd('.')
                            }
                        }
                        'CNAME' {
                            $obj | Add-Member NameHost $Matches[4].Trim().TrimEnd('.')
                        }
                        'NS' {
                            $obj | Add-Member NameHost $Matches[4].Trim().TrimEnd('.')
                        }
                        'TXT' {
                            $parts = [regex]::Matches($Matches[4], '"([^"]*)"|(\S+)') |
                            ForEach-Object {
                                if ($_.Groups[1].Success) { $_.Groups[1].Value }
                                else { $_.Groups[2].Value }
                            }
                            $obj | Add-Member Strings @($parts)
                        }
                    }

                    $results.Add($obj)
                }
            }

            return $results.ToArray()
        }

        function Get-PTR {
            param($IP, $Server)

            if ($IP -eq 'None') {
                return @{ Host = 'None'; Status = 'None' }
            }

            $thehost = $null

            if ($script:DnsMethod -eq 'ResolveDnsName') {
                $ptr = Resolve-DnsName $IP -Type PTR -Server $Server -ErrorAction SilentlyContinue | Select-Object -First 1
                $thehost = $ptr.NameHost
            }
            else {
                $thehost = (& dig "@$Server" "+short" "-x" $IP)[0]
                if ($thehost) { $thehost = $thehost.TrimEnd('.') }
            }

            if (-not $thehost) {
                return @{ Host = 'None'; Status = 'None' }
            }

            $fwd = Invoke-DnsQuery -Name $thehost -Type 'A' -Server $Server
            $ips = $fwd | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue

            $status = if ($ips -contains $IP) { '===' } else { '=/=' }

            return @{ Host = $thehost; Status = $status }
        }
    }

    process {
        # Normalize input
        $CleanDomain = $Domain -replace '^https?://', '' -replace '^www\.', '' -replace '^.*@', ''
        $CleanDomain = $CleanDomain.Split('/')[0].ToLowerInvariant().Trim()

        # Base domain heuristic
        $parts = $CleanDomain.Split('.')
        $baseDomain = if ($parts.Count -gt 2 -and $parts[-2].Length -eq 2 -and $parts[-1].Length -le 3) {
            $parts[-3..-1] -join '.'
        }
        else {
            $parts[-2, -1] -join '.'
        }

        $isSub = $baseDomain -ne $CleanDomain

        # Target queue
        if ($JustSub) {
            $targets = @($CleanDomain)
        }
        elseif ($Sub -and $isSub) {
            $targets = @($CleanDomain, $baseDomain)
        }
        else {
            $targets = @($baseDomain)
        }

        foreach ($Target in $targets) {

            $RecordTypes = if ($RecordType -ieq 'BOTH') { @('TXT', 'CNAME') } else { @($RecordType.ToUpper()) }

            # Core DNS
            $mx = Invoke-DnsQuery -Name $Target -Type 'MX' -Server $Server | Where-Object { $_.Type -eq 'MX' } | Sort-Object Preference

            $mxA = if ($mx -and $mx[0].NameExchange) {
                (Invoke-DnsQuery -Name $mx[0].NameExchange -Type 'A' -Server $Server |
                Select-Object -ExpandProperty IPAddress -First 1) ?? 'None'
            }
            else { 'None' }

            $ptr = Get-PTR -IP $mxA -Server $Server
            $ptrDisplay = if ($mxA -ne 'None') { "$($ptr.Host) $($ptr.Status) $mxA" } else { 'None' }

            $nsItems = Invoke-DnsQuery -Name $Target -Type 'NS' -Server $Server | Where-Object { $_.Type -eq 'NS' } | Select-Object -First 2
            $ns = if ($nsItems) {
                ($nsItems | ForEach-Object { "$($_.NameHost) [TTL $($_.TTL)]" }) -join " | "
            }
            else { 'None' }

            $bimi = Get-TxtValue "default._bimi.$Target" "v=BIMI1*"
            $mtaSts = Get-TxtValue "_mta-sts.$Target"   "v=STSv1*"
            $tlsRpt = Get-TxtValue "_smtp._tls.$Target" "v=TLSRPTv1*"

            foreach ($RT in $RecordTypes) {

                $spfRaw = Invoke-DnsQuery -Name $Target -Type $RT -Server $Server | Where-Object { $_.Type -eq $RT }
                $dmRaw = Invoke-DnsQuery -Name "_dmarc.$Target" -Type $RT -Server $Server | Where-Object { $_.Type -eq $RT }

                # SPF
                if ($RT -eq 'TXT') {
                    $spf = ($spfRaw | ForEach-Object { $_.Strings } | Where-Object { $_ -like "v=spf1*" } | Select-Object -First 1) ?? 'None'
                }
                else {
                    $c = $spfRaw | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                    $spf = if ($c) {
                        (Invoke-DnsQuery -Name $c.NameHost -Type 'TXT' -Server $Server |
                        ForEach-Object { $_.Strings } |
                        Where-Object { $_ -like "v=spf1*" } |
                        Select-Object -First 1) ?? 'None'
                    }
                    else { 'None' }
                }

                # DMARC
                if ($RT -eq 'TXT') {
                    $dmarc = ($dmRaw | ForEach-Object { $_.Strings } | Where-Object { $_ -like "v=DMARC1*" } | Select-Object -First 1) ?? 'None'
                }
                else {
                    $c = $dmRaw | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                    $dmarc = if ($c) {
                        (Invoke-DnsQuery -Name $c.NameHost -Type 'TXT' -Server $Server |
                        ForEach-Object { $_.Strings } |
                        Where-Object { $_ -like "v=DMARC1*" } |
                        Select-Object -First 1) ?? 'None'
                    }
                    else { 'None' }
                }

                # DKIM
                $dkimResult = 'None'
                $finalSel = if ($Selector) { $Selector } else { 'unprovided' }

                $selectors = if ($Selector) { @($Selector) } else { $DkimSelectors }

                foreach ($s in $selectors) {
                    $dk = Invoke-DnsQuery -Name "$s._domainkey.$Target" -Type $RT -Server $Server
                    if (-not $dk) { continue }

                    if ($RT -eq 'TXT') {
                        $rec = $dk | Where-Object { ($_.Strings -join '') -match "v=DKIM1" } | Select-Object -First 1
                    }
                    else {
                        $c = $dk | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                        if ($c) {
                            $rec = Invoke-DnsQuery -Name $c.NameHost -Type 'TXT' -Server $Server |
                            Where-Object { ($_.Strings -join '') -match "v=DKIM1" } |
                            Select-Object -First 1
                        }
                    }

                    if ($rec) {
                        $dkimResult = ($rec.Strings -join '')
                        $finalSel = $s
                        break
                    }
                }

                $result = [PSCustomObject]@{
                    DOMAIN      = $Target
                    SERVER      = $Server
                    RECORDTYPE  = $RT
                    MX_A        = $mxA
                    PTR         = $ptrDisplay
                    MX          = if ($mx) { ($mx | ForEach-Object { "$($_.NameExchange) [pref $($_.Preference)]" }) -join " | " } else { 'None' }
                    "SPF_$RT"   = $spf
                    "DMARC_$RT" = $dmarc
                    "DKIM_$RT"  = $dkimResult
                    SELECTOR    = $finalSel
                    BIMI        = $bimi
                    NS_First2   = $ns
                    MTA_STS     = $mtaSts
                    TLS_RPT     = $tlsRpt
                }

                if ($ExportFormat) {
                    $script:AllResults.Add($result)
                }
                else {
                    $result
                }
            }
        }
    }

    end {
        if ($ExportFormat -and $script:AllResults.Count -gt 0) {
            if ($ExportFormat -eq 'CSV') {
                $script:AllResults | Export-Csv -Path $OutputPath -NoTypeInformation -Force
            }
            else {
                $script:AllResults | ConvertTo-Json -Depth 10 | Out-File $OutputPath -Force
            }
            Write-Host "Results exported to: $OutputPath" -ForegroundColor Green
        }
    }
}