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

.PARAMETER JustSub
A switch that will return only subdomain information.

.PARAMETER Selector
The DKIM selector to use. If provided, DKIM records will be checked. If not provided, an attempt will be made to find the DKIM record. Default is unprovided.

.PARAMETER RecordType
The type of records to check for SPF, DMARC, and DKIM. Valid options are 'TXT', 'CNAME', and 'BOTH'. The default is 'TXT'.

.PARAMETER Server
The DNS server to query. The default is '8.8.8.8'.

.EXAMPLE
# Example 1: Get basic mail records for facebook.com
Get-MailRecords -Domain facebook.com
GMR -domain facebook.com

.EXAMPLE
# Example 2: Get mail records including subdomains for facebook.com
Get-MailRecords -Domain facebook.com -Sub
GMR -domain facebook.com -Sub

.EXAMPLE
# Example 3: Get mail records for a subdomain with a specific DKIM selector
Get-MailRecords -Domain cnn.facebook.com -Sub -Selector face

.EXAMPLE
# Example 4: Get DKIM records for a subdomain with an automatically determined selector
Get-MailRecords -Domain cnn.facebook.com -Selector unprovided
GMR -domain https://cnn.facebook.com -Selector unprovided

.EXAMPLE
# Example 5: Get mail records for a domain using a custom DNS server
Get-MailRecords -Domain cnn.com -Server 1.1.1.1

.EXAMPLE
# Example 6: Get CNAME records for a domain
Get-MailRecords -Domain cnn.com -RecordType cname

.EXAMPLE
# Example 7: Prompt for the domain name and retrieve mail records
GMR (Domain prompt will occur)

.EXAMPLE
# Example 8: Specify the domain and retrieve mail records
GMR -Domain https://cnn.com

.LINK
https://github.com/dcazman/Get-MailRecords

.NOTES
Author: Dan Casmas, 07/2023. Designed to work on Windows OS. Has only been tested with PowerShell versions 5.1 and 7. Requires a minimum of PowerShell 5.1.
Parts of this code were written by Jordan W.

.NOTES
To add more selectors to search, modify the $DkimSelectors array. Just below param variables.

.NOTES
Only the first 2 Nameservers results are returned if possible.
#>
function Get-MailRecords {
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
        [string]$Server = '8.8.8.8',

        [parameter(Mandatory = $false, HelpMessage = "Output is only sub domain Example: mail.facebook.com")]
        [switch]$JustSub
    )
    
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

    # Remove '@' if present
    if ([string]::IsNullOrWhiteSpace($TestDomain)) {
        try {
            $TestDomain = $Domain.Replace('@', '').Trim()
        }
        catch {
            Write-Error "Problem with $Domain as entered. Please read the command help."
            return $null
        }
    }

    # Extract the last two items in the array and join them with a dot
    if (-not $Sub -and -not $JustSub) {
        $TestDomain = $TestDomain.Split(".")[-2, -1] -join "."
    }

    # Initialize DKIM result
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

        # Check for SPF strings in the results
        $spfRecord = $SPF.Strings | Where-Object { $_ -like "v=spf1*" } -ErrorAction SilentlyContinue

        # Return the SPF string if found, otherwise return $false
        if ([string]::IsNullOrWhiteSpace($spfRecord)) {
            return $false
        }
      
        return $spfRecord
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
        $resultdmarc = If ([string]::IsNullOrWhiteSpace($DMARC)) {
            $false
        }
        Else {
            ($DMARC.Strings -like "v=DMARC1*") -join ' '
        }

        # Start of DKIM checking
        if ($Selector -ne 'unprovided') {
            # get DKIM record if exist
            $DKIM = Resolve-DnsName -Type $($TempType) -Name "$($Selector)._domainkey.$($TestDomain)" -Server $($Server) -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.type -eq $($TempType) }
            $resultdkim = If ([string]::IsNullOrWhiteSpace($DKIM)) { 
                $false
            }
            Else {
                foreach ($Item in $DKIM) {
                    if ($Item.type -eq $($TempType) -and $Item.Strings -match "v=DKIM1") {
                        [string]$Item.Strings
                        break
                    }
                }
            }
        }

        # Look for DKIM if not provided
        If ($Selector -eq 'unprovided') {
            # Break the loop if DKIM is found.
            $BreakFlag = $false
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

    if ($JustSub) {
        return  $Output
    }

    $Output

    # If Sub is true, recursively call the function with the original parameters
    If ($Sub -eq $true -and ($Domain.Split('.').count -gt 2)) {
        Get-MailRecords -Domain $Domain -Server $Server -RecordType $RecordType -Selector $SelectorHold
    }
}
