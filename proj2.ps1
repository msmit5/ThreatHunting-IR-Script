#Requires -RunAsAdministrator
# +------------------+
# │  CONFIGURATION   │
# |    AND SETUP     |
# +------------------+

$DEBUG_CLEAN = $true
$forceExecution = $true
$HASH_ALGORITHM = "MD5"

# Not exactly recommended in most cases.
$ExportUserExecutables = $false
$ExportTmpExecutables = $true   # It is more likely a executable in a tmp folder is malicious than it isn't.
$ExportableExtensions = ".exe",".py",".dll",".ps1",".bat",".msi"
$SuspiciousTMP = ".zip",".rar",".7z",".txt",".docx",".xlsx"
$SuspiciousTMP += $ExportableExtensions # Executables in tmp are suspicious


$AllowGetFirewallRules = $false # Generally, this isn't useful

# SSH Related info
# This exports all the authorized_keys files
$GetSSHData = $true
# This exports the local config files and known_hosts 
$ExportMoreSSHData = $false
# In some cases, attackers leave SSH keys as a form of persistence
# If there are more keys in an authorized_keys file than this, write output to the audit.log
$SSH_MAX_AUTH_KEYS = 0


# FILE OUTPUT FORMATS

#BASE DIRECTORY
$basedir = ".\"
$outputDestination="Exports\" # This is the folder name to export to
$outPath=$basedir+$outputDestination
$auditPath = "$outPath\audit.log"


#DEBUG: Delete audit.log and make a new one each time
if($DEBUG_CLEAN){
    Write-Output "Deleting $auditPath"
    Remove-Item $outPath
    # Remove-Item $auditPath 
}


# Create .\Exports if necessary
if(-Not(Test-Path $outPath -PathType Container)){
    New-Item -Path $outPath -ItemType Directory

    Write-Output "Writing data to $outPath and writing audit to $auditPath"
    Write-Output "Created folder: $outPath`nFolder will be used for exporting data!" |
        Out-File "$auditPath"

    # This is here because otherwise the check below would stop the program
    $forceExecution=$true
}

if($ExportUserExecutables -or $ExportTmpExecutables){
    New-Item -Path "$outPath\Executables" -ItemType Directory
}

# Checking if audit.log exists
if((Test-Path $auditPath -PathType Leaf) -And (-Not $forceExecution)){
    Write-Output "File $auditPath already exists!"
    Write-Output "Exiting! Will not continue!"
    Exit
}

# +------------------+
# │  GENERAL  INFO   │
# +------------------+


# Begin audit.log
Write-Output "Beginning at`t $([datetime]::Now.ToUniversalTime())`n" |
    Out-File -Append "$auditPath"

# General information
# This is also being written to the audit.log
Write-Output "------------ General information ------------`n" |
    Out-File -Append "$auditPath"

Write-Output "Hostname:`t$((Get-CimInstance -ClassName Win32_ComputerSystem).Name)" | 
    Out-File -Append "$auditPath"

Write-Output "Username:`t$ENV:USERNAME`n" | 
    Out-File -Append "$auditPath"

$AVStatus = Get-MpComputerStatus # This variable will be referenced again later

# Getting version info
Write-Output "Retrieving version information for OS, Powershell, and Windows Defender"
Write-Output "OS Version:`t`t`t`t$([System.Environment]::OSVersion.VersionString)" | 
    Out-File -Append "$auditPath"

Write-Output "Powershell Version:`t`t$($PSVersionTable.BuildVersion)`n" | 
    Out-File -Append "$auditPath"

Write-Output "Windows Defender Version:`t`t$($AVStatus.AMProductVersion)" |
    Out-File -Append "$auditPath"

Write-Output "Windows Defender Signatures:`t$($AVStatus.AntivirusSignatureVersion)" |
    Out-File -Append "$auditPath"

Write-Output "Windows Defender Sig. Date:`t`t$($AVStatus.AntivirusSignatureLastUpdated)`n`n" |
    Out-File -Append "$auditPath"


# Getting users
$LocalUsers = Get-LocalUser

Write-Output "Grabbing users"

Write-Output "Enabled users:" |
    Out-File -Append "$auditPath"

$LocalUsers | ForEach-Object{
    if($_.Enabled){
        Write-Output "Name:`t`t`t $($_.Name)" 
        Write-Output "Description:`t $($_.Description)`n"
    }
} | Out-File -Append "$auditPath"

# Getting disabled users
Write-Output "`nDisabled users:"  |
    Out-File -Append "$auditPath"

$LocalUsers | ForEach-Object{
    if (-not $_.Enabled){
        Write-Output "Name:`t`t`t $($_.Name)" 
        Write-Output "Description:`t $($_.Description)`n" 
    }
} | Out-File -Append "$auditPath"


# Get IP address of each interface
Get-NetIPAddress -AddressFamily IPv4 | 
    ForEach-Object {
        Write-Output "$($_.InterfaceAlias):
IPv4:`t`t`t$($_.IPAddress)
DHCP Lifetime:`t$($_.ValidLifetime)
"
    } | Out-File -Append "$auditPath"

# Dumping DNS Records
# The reason I am doing CSV, txt, and json is because 
# I personally love json and I frequently use it while automating things in python
# I use grep for analysis,
# CSV is preferred for many people, though
Write-Output "Dumping DNS Records`n"
Write-Output "Dumping DNS records to $outPath\dns.csv, $outPath\dns.txt, and $outPath\dns.json`n" |
    Tee-Object -Append -FilePath $auditPath

$dns = $(Get-DnsClientCache | Select Entry, RecordName, RecordType, Status, TimeToLive, Data)
$dns | Export-Csv -NoTypeInformation $outPath\dns.csv -Append
$dns | Out-File -Append "$outPath\dns.txt"
$dns | ConvertTo-Json | Out-File  -Append "$outPath\dns.json"


# Checking AV Status
Write-Output "------------ Windows Devender AV ------------`n" |
    Out-File -Append "$auditPath"

Write-Output "AMService Enabled:`t`t`t$($AVStatus.AMServiceEnabled)" |
    Tee-Object -Append -FilePath $auditPath
Write-Output "AntiSpyware Enabled:`t`t$($AVStatus.AntiSpywareEnabled)" |
    Tee-Object -Append -FilePath $auditPath
Write-Output "AntivirusEnabled:`t`t`t$($AVStatus.AntivirusEnabled)" |
    Tee-Object -Append -FilePath $auditPath
Write-Output "BehavioralEnabled:`t`t`t$($AVStatus.BehaviorMonitorEnabled)`n" |
    Tee-Object -Append -FilePath $auditPath

Write-Output "Windows Defender Exclusions:`nNote that no output means there is no exclusions`n" |
    Out-File -Append "$auditPath"


$AVPreferences = Get-MpPreference # This variable is referenced to determine exclusions

Write-Output "Extensions:`t`t$($AVPreferences.ExclusionExtension)`n" |
    Tee-Object -Append -FilePath $auditPath

Write-Output "IP Addresses:`t$($AVPreferences.ExclusionIpAddress)`n" |
    Tee-Object -Append -FilePath $auditPath

Write-Output "Paths:`t`t`t$($AVPreferences.ExclusionIpAddress)`n" | 
    Tee-Object -Append -FilePath $auditPath

Write-Output "Processes:`t`t$($AVPreferences.ExclusionProcess)`n" |
    Tee-Object -Append -FilePath $auditPath

# +------------------+
# │   PROCESS DATA   │
# +------------------+

#Logging in audit.log
Write-Output "Gathering Process information to processes.txt`t $([datetime]::Now.ToUniversalTime())`n" |
    Tee-Object -Append -FilePath $auditPath

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
# │  FILE  SCANNING  │
# |   (User files)   |
# +------------------+

# Enumerate through the users' Desktop, Documents, and Downloads folder
# Hash all files, and add them to a table (CSV and optionally JSON too)
# Optionally, export 
Write-Output "Hashing user files...`nThis might take a while..."
Write-Output "Hashing files in all user's Downloads, Documents, and Desktop directories" | 
    Out-File -Append $auditPath

Get-ChildItem "C:\Users" |
    ForEach-Object {
        # user Public has different file names, we need to account for that
        Get-ChildItem $_.FullName | ForEach-Object {
            if (($_.Name -eq "Downloads") -or ($_.Name -eq "Documents") -or ($_.name -eq "Desktop")){
                Get-ChildItem $_.FullName -Recurse| ForEach-Object {
                    if (-not ((Get-Item $_.FullName) -is [System.IO.DirectoryInfo])){
                        Get-FileHash -Path "$($_.FullName)" -Algorithm MD5|
                            Export-Csv -Append $outPath\hashes.csv
                    }

                    # Export executables and scripts if found in these files
                    # Only do so if enabled ($ExportUserExecutables = $true)
                    # -export is added to the name to make it harder to accidentally run a potentially
                    # malicious file that is grabbed by this script
                    if($ExportUserExecutables){
                        if ($ExportableExtensions.Contains($_.Extension)){
                            Copy-Item -Path $_.FullName -Destination "$outPath\executables\$($_.name)-export"
                    }
                }
            } 
        } 
    }
}


# +------------------+
# │  FILE  SCANNING  │
# |   (Temp files)   |
# +------------------+
# Determining all temp locations
[array]$searchable = Get-ChildItem "C:\Users" | 
    ForEach-Object{
        # Because Public doesn't have an appdata or tmp, it is ignored
        if(-not ($_.name -eq "Public")){
            "$($_.FullName)\AppData\Local\Temp"
        }
    }
$searchable += "C:\Windows\Temp"

Write-Output "Examining temporary folders:" |
    Tee-Object -Append $auditPath

Get-ChildItem -Recurse $searchable | ForEach-Object {

    # Check if a file in a temp directory has a suspicious extension
    if($SuspiciousTMP.Contains($_.Extension)){
        Write-Output "Possible suspicious temp file found: $($_.fullName)" |
            Tee-Object -Append -FilePath $auditPath
        
        # Hash the suspicious file
        Get-FileHash -Path "$($_.FullName)" -Algorithm MD5|
            Export-Csv -Append $outPath\hashes.csv
    }

    # If enabled, export executables from temp
    if($ExportTmpExecutables){
        if($ExportableExtensions.Contains($_.Extension)){
            Copy-Item -Path $_.FullName -Destination "$outPath\Executables\$($_.name)-export"
        }
    }
}


# BELOW HERE ARE POTENTIALLY EXTRANEOUS OPERATIONS
# THEY ARE ORDERED BY USEFULNESS
# SOME OF THEM ARE INCLUDED BECAUSE THEY MAY BE USEFUL IN A COMPETITION SETTING!

# +------------------+
# │  GET .SSH INFO   │
# |    (Optional)    |
# +------------------+
if($GetSSHData){
    # Test for each user
    Write-Output "Retrieving SSH Data" | 
        Tee-Object -Append -FilePath "$auditPath"

    $count = 0
    # Enumerate through the users folder and search through their ssh files
    Get-ChildItem "C:\Users" |
        ForEach-Object {
            # Test if the .ssh directory exists.
            if (Test-Path "$($_.FullName)\.ssh" -PathType Container){

                # Check if there is an authorized keys file
                if (Test-Path "$($_.FullName)\.ssh\authorized_keys"){
                    Write-Output "authorized_keys file found for $($_.Name)! File is being copied to Exports!" |
                        Tee-Object -Append -FilePath $auditPath
                    
                    Copy-Item -Path "$($_.FullName)\.ssh\authorized_keys" -Destination "$outPath\authorized_keys-$($_.Name)"

                    # Getting an accurate count of entries in the authorized_keys file
                    # There is supposed to be one entry per line (and each entry is one line)
                    # However, whitespace is ignored, and I don't want to count it!
                    #https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/ignoring-empty-lines
                    $lc = (Get-Content -Path "$($_.FullName)\.ssh\authorized_keys" | 
                        Where-Object { $_.Trim() -ne '' } |
                        Measure-Object -Line).Lines
                    
                    # If we have too many keys in the authorized_keys, it should be examined
                    if ($lc -gt $SSH_MAX_AUTH_KEYS){
                        Write-Output "There are more entries in $($_.FullName)\authorized_keys than allowed!" |
                            Tee-Object -Append -FilePath $auditPath
                    }
                }
                if (Test-Path "$($_.FullName)\.ssh\known_hosts"){
                    Write-Output "known_hosts file found for $($_.Name)! File is being copied to Exports!" |
                        Tee-Object -Append -FilePath $auditPath

                    Copy-Item -Path "$($_.FullName)\.ssh\known_hosts" -Destination "$outPath\known_hosts-$($_.Name)"
                }

                if (Test-Path "$($_.FullName)\.ssh\config"){
                    Write-Output "ssh config file found for $($_.Name)! File is being copied to Exports!" |
                        Tee-Object -Append -FilePath $auditPath

                    Copy-Item -Path "$($_.FullName)\.ssh\config" -Destination "$outPath\ssh_config-$($_.Name)"
                }
                $count++
            }
        } #End ForEach
    if($count -eq 0){
        Write-Output "No SSH files found!" |
            Tee-Object -Append -FilePath $auditPath
    }
}


# +------------------+
# │  FIREWALL RULES  │
# |    (Optional)    |
# +------------------+
# Once again, I am writing to a CSV, TXT, and JSON file
# Normally, I would annotate the text file a bit in a for-each, but as a unix person who likes iptables,
# I am unfamiliar with windows firewall.
if ($AllowGetFirewallRules){
    Write-Output "Dumping firewall rules to $outPath\firewall-rules.csv, $outPath\firewall-rules.txt, and $outPath\firewall-rules.json" |
        Tee-Object -Append -FilePath $auditPath

    $firewallRules = Get-NetFirewallRule

    $firewallRules | Out-File "$outPath\firewall-rules.txt"
    $firewallRules | Export-Csv "$outPath\firewall-rules.csv"
    $firewallRules | ConvertTo-Json |
        Out-File "$outPath\firewall-rules.json"

}