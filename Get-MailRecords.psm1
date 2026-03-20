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

        [parameter(Mandatory = $false)]
        [alias ('s')]
        [switch]$Sub,

        [parameter(Mandatory = $false)]
        [alias ('js')]
        [switch]$JustSub,

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [alias ('sel')]
        [string]$Selector = 'unprovided',

        [parameter(Mandatory = $false)]
        [alias ('dkim')]
        [string[]]$DkimSelectors = @(
            "default", "s", "s1", "s2", "selector1", "selector2", "pps1", "google",
            "everlytickey1", "everlytickey2", "eversrv", "k1", "mxvault", "dkim",
            "mail", "s1024", "s2048", "s4096"
        ),

        [parameter(Mandatory = $false)]
        [ValidateSet('TXT', 'CNAME', 'BOTH')]
        [ValidateNotNullOrEmpty()]
        [alias ('r')]
        [string]$RecordType = 'TXT',

        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [alias ('srv')]
        [string]$Server = '8.8.8.8',

        [parameter(Mandatory = $false)]
        [alias ('e')]
        [string]$Export
    )

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
                Write-Error "Export parameter must be either a filename with .csv or .json extension, or 'CSV'/'JSON' for auto-generated filename."
                return
            }
        }
    }

    process {
        if ($script:DnsMethod -eq 'none') {
            return $null
        }

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

            [string]$resultsNS = ($OutNS | Select-Object -First 2 | ForEach-Object { "$($_.NameHost) [TTL $($_.TTL)]" }) -join " | "
            return $resultsNS
        }

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

        if ($Selector -ne 'unprovided') {
            $Selector = $Selector.ToLowerInvariant()
        }

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

        if (-not $Sub -and -not $JustSub) {
            $parts = $TestDomain.Split(".")
            if ($parts.Count -gt 2 -and $parts[-2].Length -eq 2 -and $parts[-1].Length -le 3) {
                $TestDomain = $parts[-3..-1] -join "."
            }
            else {
                $TestDomain = $parts[-2, -1] -join "."
            }
        }

        $resultdkim = $false

        $RecordTypeTest = @()
        if ($RecordType -eq 'BOTH') {
            $RecordTypeTest = @('TXT', 'CNAME')
        }
        else {
            $RecordTypeTest = @($RecordType.ToUpper())
        }

        $resultA = $null -ne (Invoke-DnsQuery -Name $TestDomain -Type 'A' -Server $Server | Where-Object { $_.Type -eq 'A' })

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
            $resultmx = ($formattedRecords | ForEach-Object { "$($_.Name) [pref $($_.Preference), TTL $($_.TTL)]" }) -join " | "
        }
        else {
            Write-Verbose "No MX records found for domain: $Domain"
            $resultmx = $false
        }

        $DkimExplicit = $PSBoundParameters.ContainsKey('DkimSelectors')
        $SelectorHold = $Selector

        $Output = $RecordTypeTest | ForEach-Object {
            $TempType = $_

            $resultsNS = Get-NS -Domain $TestDomain -Server $Server
            $resultspf = Get-SPF -Domain $TestDomain -Server $Server -Type $TempType

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

            if ($resultdkim -eq $false) {
                $Selector = if ($DkimExplicit) { $DkimSelectors -join ', ' } else { $SelectorHold }
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
