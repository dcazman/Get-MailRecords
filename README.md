.SYNOPSIS
A PowerShell function that performs DNS queries A, MX, NS, SPF, DMARC and DKIM DNS on given domain name, email address or URL. This function has an alias GMR.

.DESCRIPTION
This function performs various checks on a given domain name,email address,or URL. It checks for the existence of DNS records A,MX,NS,SPF,DMARC,and DKIM.
This function will check for record type TXT,CNAME,and BOTH for SPF,DMARC,and DKIM.
This function will attempt to find the DKIM record if the selector is not provided.
This function has an alias GMR.
Add this function to your powershell profile then run like the following.
Note: More selectors to search can be added to $DkimSelectors right at the top of the function.

.PARAMETER Domain
The full domain name,email address,or URL to check.

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
