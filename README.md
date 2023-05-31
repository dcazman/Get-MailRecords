# Get-MailRecords
A PowerShell function that tries to find if there are the following DNS records A, MX, SPF, DMARC and DKIM.
Add this function to your powershell profile then run like the following. 

How to use:
get-mailrecords -domain facebook.com

switch -sub will test the subdomain
get-mailrecords -domain cnn.facebook.com -sub

string -selector will test dkim with the string provided
get-mailrecords -domain cnn.facebook.com -selector face

switch -flag will return simple true of false
get-mailrecords -domain cnn.facebook.com -flag

string -server will use whatever value is inputed. must be ip4 default is 8.8.8.8
get-mailrecords -domain cnn.com -server 1.1.1.1

string -recordType can be set to txt or cname and will try to find the related records. Default is TXT.
get-mailrecords -domain cnn.com -recordType cname

Examples:
get-mailrecords -domain cnn.facebook.com -sub -flag -selector face
get-mailrecords -domain cnn.facebook.com -sub -selector face
get-mailrecords -domain cnn.facebook.com -selector face
get-mailrecords -domain cnn.facebook.com -sub -flag
get-mailrecords -domain cnn.facebook.com -sub -flag -selector face
get-mailrecords -domain cnn.facebook.com -sub -selector face
get-mailrecords -domain cnn.facebook.com -selector face

Results if any comes back as an object and on host.

Note : You can enter the full domain name, an email address or an entire URL for -domain. 

This function has an alias GMR.
