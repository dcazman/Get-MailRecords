<#
.SYNOPSIS
A PowerShell function that performs DNS queries A, MX, NS, SPF, DMARC and DKIM on a given domain name, email address or URL. 
This function has an alias GMR.

.DESCRIPTION
This function performs various checks on a given domain name,email address,or URL. It checks for the existence of DNS records A,MX,NS,SPF,DMARC,and DKIM.
This function can check for record type TXT,CNAME,and BOTH for SPF,DMARC,and DKIM.
This function will attempt to find the DKIM record if the selector is not provided.
This function has an alias GMR.
Add this function to your powershell profile then run like the following.
Note: More selectors to search can be added to $DkimSelectors right at the top of the function.
Note: The first 2 NS results are returned if possible.

.PARAMETER Domain
The full domain name,email address,or URL to check. MANDATORY parameter.

.PARAMETER Sub
Allow subdomain. If specified,subdomains will be included in the checks.

.PARAMETER Selector
The DKIM selector to use. If provided,DKIM records will be checked. If not provided,an attempt will be made to find the DKIM record.

.PARAMETER RecordType
The type of records to check for SPF,DMARC,and DKIM. Valid options are 'TXT','CNAME',and 'BOTH'. The default is 'TXT'.

.PARAMETER Server
The DNS server to query. The default is '8.8.8.8'.

.EXAMPLE
Get-MailRecords -Domain facebook.com
GMR -domain facebook.com

.EXAMPLE
Get-MailRecords -Domain facebook.com -Sub

.EXAMPLE
Get-MailRecords -Domain cnn.facebook.com -Sub -Selector face

.EXAMPLE
Get-MailRecords -Domain cnn.facebook.com -Selector face
GMR -domain https://cnn.facebook.com -Selector face

.EXAMPLE
Get-MailRecords -Domain cnn.com -Server 1.1.1.1

.EXAMPLE
Get-MailRecords -Domain cnn.com -RecordType cname

.EXAMPLE
GMR (Domain prompt will occur)
GMR -Domain cnn.com

#>
function Get-MailRecords {
    #Requires -Version 5.1
    [Alias("GMR")]
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true,
            HelpMessage = "Enter the full domain name an example is Facebook.com,enter an entire email address or enter full URL.")]
        [ValidateScript({
                if ($_ -like "*.*") {
                    return $true
                }
                else {
                    Throw [System.Management.Automation.ValidationMetadataException] "Enter the full domain name,an example is Facebook.com,enter an entire email address or enter full URL."
                    return $false
                }
            })][string]$Domain,
        [parameter(Mandatory = $false,
            HelpMessage = "Allow subdomain. Example mail.facebook.com")][switch]$Sub,
        [parameter(Mandatory = $false,
            HelpMessage = "DKIM selector. DKIM won't be checked without this string.")][string]$Selector = 'unprovided',
        [parameter(Mandatory = $false,
            HelpMessage = "Looks for record type TXT or CNAME or BOTH for SPF,DMARC and DKIM if -Selector is used. The default record type is TXT.")]
        [ValidateSet('TXT', 'CNAME', 'BOTH')][ValidateNotNullOrEmpty()][string]$RecordType = 'TXT',
        [parameter(Mandatory = $false,
            HelpMessage = "Server to query the default is 8.8.8.8")][ValidateNotNullOrEmpty()][string]$Server = '8.8.8.8'
    )

    <#
    Author: Dan Casmas,07/2023. Designed to work on Windows OS. Has only been tested with PowerShell versions 5.1 and 7. Requires a minimum of PowerShell 5.1.
    Parts of this code were written by Jordan W.
    #>

    # Add more selectors here you want this function to search them.
    $DkimSelectors = $null
    $DkimSelectors = @(
        "default",
        "s",
        "s1",
        "s2",
        "selector1", # Microsoft
        "selector2", # Microsoft
        "pps1", #Proofpoint
        "google", # Google
        "everlytickey1", # Everlytic
        "everlytickey2", # Everlytic
        "eversrv", # Everlytic OLD selector
        "k1", # Mailchimp / Mandrill
        "mxvault", # Global Micro
        "dkim", # Hetzner
        "mail"
    )

    # Check for Resolve-DnsName
    if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        Write-Error "There is a problem with Resolve-DnsName and this function can't continue."
        return
    }
    
    # if email address pull down to domain,uri pull down to domain and if not test domain
    $TestDomain = $null
    Try {
        [string]$TestDomain = ([System.Uri]$Domain).Host.TrimStart('www.')
    }
    Catch {
        try {
            [string]$TestDomain = ([Net.Mail.MailAddress]$Domain).Host
        }
        catch {
            [string]$TestDomain = $Domain
        }
    }
    
    # Removes @
    If ([string]::IsNullOrWhiteSpace($TestDomain)) {
        Try { 
            [string]$TestDomain = $Domain.Replace('@', '').Trim()
        }
        Catch {
            Write-Error "Problem with $Domain as entered. Please read command help."
            Return
        }
    }

    # get the last two items in the array and join them with dot
    if (-not $Sub) {
        [string]$TestDomain = $TestDomain.Split(".")[-2, -1] -join "."
    }
    
    # places a value other than true or false if dkim selector is not provided.
    $resultdkim = 'unfound'

    # If both for record type then loop through.
    $RecordTypeTest = @()
    if ($RecordType -eq 'BOTH') {
        $RecordTypeTest = @(
            'TXT',
            'CNAME'
        )
    }
    Else {
        $RecordTypeTest = $RecordType.ToUpper()
    }
    
    # get A record if exist
    [string]$resultA = If (Resolve-DnsName -Name $TestDomain -Type 'A' -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq 'a' } ) { $true } Else { $false }

    # get MX record if exist
    $Mx = Resolve-DnsName -Name $TestDomain -Type 'MX' -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Sort-Object -Property Preference 
    if ([string]::IsNullOrWhiteSpace($Mx.NameExchange)) {
        $resultmx = $false
    }
    Else {
        $Outmx = foreach ($record in $Mx) {
            $record | Select-object @{n = "Name"; e = { $_.NameExchange } }, @{n = "Pref"; e = { $_.Preference } }, TTL
        }
        [string]$resultmx = ($Outmx | Out-String).trimend("`r`n").Trim()
    }

    # get NS record if exist
    $NS = Resolve-DnsName -Name $TestDomain -Type 'NS' -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($NS.NameHost)) {
        $resultsNS = $false
    }
    Else {
        $OutNS = foreach ($Item in $NS) {
            $Item | Select-object NameHost, TTL
        }
        [string]$resultsNS = ($OutNS | Select-Object -First 2 | Out-String).trimend("`r`n").Trim()
    }

    $SelectorHold = $Selector

    # Loop and output
    $Output = @{}
    $Output = $RecordTypeTest | ForEach-Object {
        #Hold onto record type
        $TempType = $null
        $TempType = $($_)

        # get SPF record if exist
        $SPF = $null
        $SPF = Resolve-DnsName -Name $TestDomain -Type $($TempType) -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue 
        $resultspf = $false
        foreach ($Item in $SPF) {
            if ($Item.strings -match "v=spf1" -and $Null -ne $Item.Strings -and $Item.type -eq $($TempType)) {
                [string]$resultspf = $Item.Strings
                break
            }
        }

        # get DMARC record if exist
        $DMARC = $null
        $resultdmarc = $null
        $DMARC = Resolve-DnsName -Name "_dmarc.$($TestDomain)" -Type $($TempType) -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq $($TempType) }
        if ([string]::IsNullOrWhiteSpace($DMARC)) {
            $resultdmarc = $false
        }
        Else {
            foreach ($Item in $DMARC) {
                if ($Item.type -eq $($TempType) -and $null -ne $Item.Strings -and $Item.strings -match "v=DMARC1") {
                    [string]$resultdmarc = $Item.Strings
                    break
                }
            }
        }

        if ($Selector -ne 'unprovided') {
            # get DKIM record if exist
            $DKIM = Resolve-DnsName -Type $($TempType) -Name "$($Selector)._domainkey.$($TestDomain)" -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq $($TempType) }
            $resultdkim = $false
            foreach ($Item in $DKIM) {
                if ($Item.type -eq $($TempType) -and $null -ne $Item.Strings -and $Item.Strings -match "v=DKIM1") {
                    [string]$resultdkim = $Item.Strings
                    break
                }
            }
        }

        If ($Selector -eq 'unprovided' -and ($resultdkim -eq $false -or $resultdkim -eq 'unfound')) {
            # Break the loop if DKIM is found.
            $BreakFlag = $false
            # Look for DKIM if not provided
            foreach ($line in $DkimSelectors) {
                # get DKIM record if exist
                $DKIM = $null
                $DKIM = Resolve-DnsName -Type $($TempType) -Name "$($line)._domainkey.$($TestDomain)" -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue
                $Item = $null
                foreach ($Item in $DKIM) {
                    if ($Item.type -eq $($TempType) -and $null -ne $Item.Strings -and $Item.Strings -match "v=DKIM1") {
                        if ($Logical) {
                            $resultdkim = $true
                        }
                        Else {
                            [string]$resultdkim = $Item.Strings
                            $Selector = $line
                            $BreakFlag = $true
                            break
                        }
                    }
                    $Item = $null
                }
                If ($BreakFlag) {
                    break
                }
            }
        }

        # Holds the selector
        if ($null -ne $SelectorHold -and ($resultdkim -eq $false )) {
            $Selector = $SelectorHold
            $resultdkim = 'unfound'
        }

        # Gathers the object to object
        [PSCustomObject]@{
            A                 = $resultA
            MX                = $resultmx
            "SPF_$TempType"   = $resultspf
            "DMARC_$TempType" = $resultdmarc
            "DKIM_$TempType"  = $resultdkim
            SELECTOR          = $Selector
            DOMAIN            = $TestDomain
            RECORDTYPE        = $($TempType)
            SERVER            = $Server
            NS_First2         = $resultsNS
        } 
    }

    return $Output
}
