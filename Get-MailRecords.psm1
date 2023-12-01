<#
.SYNOPSIS
A PowerShell function that performs DNS queries A, MX, NS, SPF, DMARC, and DKIM on a given domain name, email address, or URL.
This function has an alias GMR.

.DESCRIPTION
This function performs various checks on a given domain name, email address, or URL. It checks for the existence of DNS records A, MX, NS, SPF, DMARC, and DKIM.
This function can check for record types TXT, CNAME, and BOTH for (SPF, DMARC, and DKIM).
This function will attempt to find the DKIM record if the DKIM selector is not provided.
This function has an alias GMR.
Add this function to your PowerShell profile then run like the examples below.

.PARAMETER Domain
The full domain name, email address, or URL to retrieve. MANDATORY parameter.

.PARAMETER Sub
Allow subdomain. If specified, subdomains will be included in the checks.

.PARAMETER Selector
The DKIM selector to use. If provided, DKIM records will be checked. If not provided, an attempt will be made to find the DKIM record. Default is unprovided.

.PARAMETER RecordType
The type of records to check for SPF, DMARC, and DKIM. Valid options are 'TXT', 'CNAME', and 'BOTH'. The default is 'TXT'.

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

.EXAMPLE
GMR -Domain cnn.com

.LINK
https://github.com/dcazman/Get-MailRecords

.NOTES
Author: Dan Casmas, 07/2023. Designed to work on Windows OS. Has only been tested with PowerShell versions 5.1 and 7. Requires a minimum of PowerShell 5.1.
Parts of this code were written by Jordan W.

.NOTES
To add more selectors to search go just below param variables.

.NOTES
The first 2 Nameservers results are returned if possible.
#>
function Get-MailRecords {
    #Requires -Version 5.1
    [Alias("GMR")]
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $true, HelpMessage = "Enter the full domain name, email address, or URL.")]
        [ValidateScript({
                if ($_ -like "*.*") {
                    return $true
                }
                else {
                    Throw [System.Management.Automation.ValidationMetadataException] "Enter the full domain name, email address, or URL."
                    return $false
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
        [string]$Server = '8.8.8.8'
    )
    
    # Check if selector is provided
    if ($Selector -eq 'unprovided') {
        # List of DKIM selectors
        $DkimSelectors = @(
            "default",
            "s",
            "s1",
            "s2",
            "selector1", # Microsoft
            "selector2", # Microsoft
            "pps1", # Proofpoint
            "google", # Google
            "everlytickey1", # Everlytic
            "everlytickey2", # Everlytic
            "eversrv", # Everlytic OLD selector
            "k1", # Mailchimp / Mandrill
            "mxvault", # Global Micro
            "dkim", # Hetzner
            "mail"
        )
    }
    
    # Check for Resolve-DnsName
    if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        Write-Error "There is a problem with Resolve-DnsName, and this function can't continue."
        return $null
    }
    
    # if email address pull down to domain, uri pull down to domain and if not test domain
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
    
    # Removes @
    if ([string]::IsNullOrWhiteSpace($TestDomain)) {
        try {
            $TestDomain = $Domain.Replace('@', '').Trim()
        }
        catch {
            Write-Error "Problem with $Domain as entered. Please read the command help."
            return $null
        }
    }
    
    # get the last two items in the array and join them with a dot
    if (-not $Sub) {
        $TestDomain = $TestDomain.Split(".")[-2, -1] -join "."
    }
    
    # places a value other than true or false if DKIM selector is not provided.
    $resultdkim = 'unfound'
    
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
    
    # Hold the selector
    $SelectorHold = $Selector
    
    # Loop and output
    $Output = $RecordTypeTest | ForEach-Object {
        $TempType = $_
    
        # get A record if exist
        $resultA = if (Resolve-DnsName -Name $TestDomain -Type 'A' -Server $Server -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq 'a' }) { $true } else { $false }
    
        # get MX record if exist
        $Mx = Resolve-DnsName -Name $TestDomain -Type 'MX' -Server $Server -DnsOnly -ErrorAction SilentlyContinue | Sort-Object -Property Preference
        $resultmx = if ([string]::IsNullOrWhiteSpace($Mx.NameExchange)) {
            $false
        }
        else {
            $Outmx = foreach ($record in $Mx) {
                $record | Select-Object @{n = "Name"; e = { $_.NameExchange } }, @{n = "Pref"; e = { $_.Preference } }, TTL
            }
            ($Outmx | Out-String).TrimEnd("`r`n").Trim()
        }
    
        # get NS record if exist
        $resultsNS = Get-NS -Domain $TestDomain -Server $Server
    
        # Test parent for NS if -sub and no NS returned
        if ($resultsNS -eq $false -and $Sub) {
            $resultsNS = Get-NS -Domain ($Domain.Split(".")[-2, -1] -join ".") -Server $Server
        }
    
        # get SPF record if exist
        $SPF = Resolve-DnsName -Name $TestDomain -Type $TempType -Server $Server -DnsOnly -ErrorAction SilentlyContinue
        $resultspf = ($SPF.Strings -like "v=spf1*" | Out-String).TrimEnd("`r`n").Trim()
    
        # get DMARC record if exist
        $DMARC = Resolve-DnsName -Name "_dmarc.$TestDomain" -Type $TempType -Server $Server -DnsOnly -ErrorAction SilentlyContinue
        $resultdmarc = ($DMARC.strings -like "v=DMARC1*" | Out-String).TrimEnd("`r`n").Trim()
    
        # Start of DKIM checking
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
                $DKIM = Resolve-DnsName -Type $($TempType) -Name "$($line)._domainkey.$($TestDomain)" -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq $TempType -and $_.Strings -match "v=DKIM1" }
                foreach ($Item in $DKIM) {
                    [string]$resultdkim = $Item.Strings
                    $Selector = $line
                    $BreakFlag = $true
                    break
                }
                If ($BreakFlag) {
                    break
                }
            }
        }
    
        # Holds the selector
        if ($resultdkim -eq $false) {
            $Selector = $SelectorHold
            $resultdkim = 'unfound'
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
    
    # Final
    return $Output
}
