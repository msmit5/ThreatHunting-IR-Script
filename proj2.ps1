# +------------------+
# │  CONFIGURATION   │
# +------------------+

# Misc
# $AllowBrowserData = "True"
# $AllowGetDownloadEXEs = "True"
# $BeginScan = "False"


# +------------------+
# │  GENERAL  INFO   │
# +------------------+
# Begin audit.log
Write-Output "Beginning at`t $([datetime]::Now.ToUniversalTime())`n" |
    Out-File ".\audit.log"

# General information
# This is also being written to the audit.log
Write-Output "------------ General information ------------`n" |
    Out-File -Append ".\audit.log"

Write-Output "Hostname:`t$((Get-CimInstance -ClassName Win32_ComputerSystem).Name)" | 
    Out-File -Append ".\audit.log"

Write-Output "Username:`t$ENV:USERNAME`n" | 
    Out-File -Append ".\audit.log"

$AVStatus = Get-MpComputerStatus # This variable will be referenced later

# Getting version info
Write-Output "OS Version:`t`tTODO!" | 
    Out-File -Append ".\audit.log"

Write-Output "Powershell Version:`tTODO" | 
    Out-File -Append ".\audit.log"

Write-Output "Windows Defender Version:`t$($AVStatus.AMProductVersion)" |
    Out-File -Append ".\audit.log"

Write-Output "Windows Defender Signatures:`t$($AVStatus.AntivirusSignatureVersion)" |
    Out-File -Append ".\audit.log"

Write-Output "Windows Defender Sig. Date:`t$($AVStatus.AntivirusSignatureLastUpdated)" |
    Out-File -Append ".\audit.log"


# Get IP address of each interface
Get-NetIPAddress -AddressFamily IPv4 | 
    ForEach-Object {
        Write-Output "$($_.InterfaceAlias):
IPv4:`t`t`t$($_.IPAddress)
DHCP Lifetime:`t$($_.ValidLifetime)
"
    } | Out-File -Append ".\audit.log"

#DNS
#TODO
# Checking AV Status
Write-Output "------------ Windows Devender AV ------------`n" |
    Out-File -Append ".\audit.log"

Write-Output "AMService Enabled:`t`t`t$($AVStatus.AMServiceEnabled)
AntiSpyware Enabled:`t`t$($AVStatus.AntiSpywareEnabled)
AntivirusEnabled:`t`t`t$($AVStatus.AntivirusEnabled)
BehavioralEnabled:`t`t`t$($AVStatus.BehaviorMonitorEnabled)
    " |
    Out-File -Append ".\audit.log"

# +------------------+
# │   PROCESS DATA   │
# +------------------+

#Logging in audit.log
Write-Output "Gathering Process information`nto processes.txt`t $([datetime]::Now.ToUniversalTime())`n" |
    Out-File -Append ".\audit.log"

# Snapshot of running processes
Get-Process | Out-File ".\processes.txt"

Write-Output "`n`n" |
    Out-File -Append ".\processes.txt"

# Startup processes
Write-Output "Gathering startup processes to processes.txt`n" |
    Out-File -Append ".\processes.txt"
    
Get-CimInstance Win32_StartupCommand | 
    ForEach-Object {
        Write-Output "$($_.Name):
cmd:`t`t$($_.Command)
loc:`t`t$($_.Location)
usr:`t`t$($_.User)`n"
    } | Out-File -Append ".\processes.txt" 

Write-Output "`n`n" |
    Out-File -Append ".\processes.txt"



# +-------------------+
# │ FUNTIONS N THINGS │
# +-------------------+