#Requires -RunAsAdministrator
# +------------------+
# │  CONFIGURATION   │
# |    AND SETUP     |
# +------------------+

# Misc
# $AllowBrowserData = $true 
# $AllowGetDownloadEXEs = $true 
# $BeginScan = $true 
$GetSSHData = $true
$AllowGetFirewallRules = $true
$forceExecution = $true


# FILE OUTPUT FORMATS

#BASE DIRECTORY
$basedir = ".\"
$outputDestination="Exports\" # This is the folder name to export to
$outPath=$basedir+$outputDestination

# Create .\Exports if necessary
if(-Not(Test-Path $outPath -PathType Container)){
    New-Item -Path $outPath -ItemType Directory

    Write-Output "Created folder: $outPath" |
        Out-File "$outPath\audit.log"

    # This is here because otherwise the check below
    $forceExecution=$true
}

# +------------------+
# │  GENERAL  INFO   │
# +------------------+

# Checking if audit.log exists
if((Test-Path $outPath\audit.log -PathType Leaf) -And (-Not $forceExecution)){
    Write-Output "File $outPath\audit.log already exists!"
    Write-Output "Exiting! Will not continue!"
    Exit
}
# Begin audit.log
Write-Output "Beginning at`t $([datetime]::Now.ToUniversalTime())`n" |
    Out-File -Append "$outPath\audit.log"

# General information
# This is also being written to the audit.log
Write-Output "------------ General information ------------`n" |
    Out-File -Append "$outPath\audit.log"

Write-Output "Hostname:`t$((Get-CimInstance -ClassName Win32_ComputerSystem).Name)" | 
    Out-File -Append "$outPath\audit.log"

Write-Output "Username:`t$ENV:USERNAME`n" | 
    Out-File -Append "$outPath\audit.log"

$AVStatus = Get-MpComputerStatus # This variable will be referenced later

# Getting version info
Write-Output "OS Version:`t`t`t`t$([System.Environment]::OSVersion.VersionString)" | 
    Out-File -Append "$outPath\audit.log"

Write-Output "Powershell Version:`t`t$($PSVersionTable.BuildVersion)`n" | 
    Out-File -Append "$outPath\audit.log"

Write-Output "Windows Defender Version:`t`t$($AVStatus.AMProductVersion)" |
    Out-File -Append "$outPath\audit.log"

Write-Output "Windows Defender Signatures:`t$($AVStatus.AntivirusSignatureVersion)" |
    Out-File -Append "$outPath\audit.log"

Write-Output "Windows Defender Sig. Date:`t`t$($AVStatus.AntivirusSignatureLastUpdated)`n`n" |
    Out-File -Append "$outPath\audit.log"


# Get IP address of each interface
Get-NetIPAddress -AddressFamily IPv4 | 
    ForEach-Object {
        Write-Output "$($_.InterfaceAlias):
IPv4:`t`t`t$($_.IPAddress)
DHCP Lifetime:`t$($_.ValidLifetime)
"
    } | Out-File -Append "$outPath\audit.log"

# Dumping DNS Records
# The reason I am doing CSV, txt, and json is because 
# I personally love json and I frequently use it while automating things in python
# I use grep for analysis,
# CSV is preferred for many people, though
Write-Output "Dumping DNS records to $outPath\dns.csv, $outPath\dns.txt, and $outPath\dns.json`n" |
    Out-File -Append "$outPath\audit.log"

$dns = $(Get-DnsClientCache | Select Entry, RecordName, RecordType, Status, TimeToLive, Data)
# $dns | Export-Csv -NoTypeInformation $outPath\dns.csv -Append
$dns | Out-File -Append "$outPath\dns.txt"
$dns | ConvertTo-Json | Out-File  -Append "$outPath\dns.json"


# Checking AV Status
Write-Output "------------ Windows Devender AV ------------`n" |
    Out-File -Append "$outPath\audit.log"

Write-Output "AMService Enabled:`t`t`t$($AVStatus.AMServiceEnabled)" |
    Out-File -Append "$outPath\audit.log"
Write-Output "AntiSpyware Enabled:`t`t$($AVStatus.AntiSpywareEnabled)" |
    Out-File -Append "$outPath\audit.log"
Write-Output "AntivirusEnabled:`t`t`t$($AVStatus.AntivirusEnabled)" |
    Out-File -Append "$outPath\audit.log"
Write-Output "BehavioralEnabled:`t`t`t$($AVStatus.BehaviorMonitorEnabled)`n" |
    Out-File -Append "$outPath\audit.log"

Write-Output "Windows Defender Exclusions:`nNote that no output means there is no exclusions`n" |
    Out-File -Append "$outPath\audit.log"


$AVPreferences = Get-MpPreference # This variable is referenced to determine exclusions

Write-Output "Extensions:`t`t$($AVPreferences.ExclusionExtension)`n" |
    Out-File -Append "$outPath\audit.log"

Write-Output "IP Addresses:`t$($AVPreferences.ExclusionIpAddress)`n" |
    Out-File -Append "$outPath\audit.log"

Write-Output "Paths:`t`t`t$($AVPreferences.ExclusionIpAddress)`n" | 
    Out-File -Append "$outPath\audit.log"

Write-Output "Processes:`t`t$($AVPreferences.ExclusionProcess)`n" |
    Out-File -Append "$outPath\audit.log"


# +------------------+
# │   PROCESS DATA   │
# +------------------+

#Logging in audit.log
Write-Output "Gathering Process information`nto processes.txt`t $([datetime]::Now.ToUniversalTime())`n" |
    Out-File -Append "$outPath\audit.log"

# Snapshot of running processes
Get-Process | Out-File "$outPath\processes.txt"

Write-Output "`n`n" |
    Out-File -Append "$outPath\processes.txt"

# Startup processes
Write-Output "Gathering startup processes to processes.txt`n" |
    Out-File -Append "$outPath\processes.txt"
    
Get-CimInstance Win32_StartupCommand | 
    ForEach-Object {
        Write-Output "$($_.Name):
cmd:`t`t$($_.Command)
loc:`t`t$($_.Location)
usr:`t`t$($_.User)`n"
    } | Out-File -Append "$outPath\processes.txt" 

Write-Output "`n`n" |
    Out-File -Append "$outPath\processes.txt"



# +------------------+
# │  FIREWALL RULES  │
# |    (Optional)    |
# +------------------+
# Once again, I am writing to a CSV, TXT, and JSON file
# Normally, I would annotate the text file a bit in a for-each, but as a unix person who likes iptables,
# I am unfamiliar with windows firewall.
if ($AllowGetFirewallRules){
Write-Output "Dumping firewall rules to $outPath\firewall-rules.csv, $outPath\firewall-rules.txt, and $outPath\firewall-rules.json" |
    Out-File -Append "audit.log"

$firewallRules = Get-NetFirewallRule

$firewallRules | Out-File "$outPath\firewall-rules.txt"
$firewallRules | Export-Csv "$outPath\firewall-rules.csv"
$firewallRules | ConvertTo-Json |
    Out-File "$outPath\firewall-rules.json"

}

# +-------------------+
# │ FUNTIONS N THINGS │
# +-------------------+