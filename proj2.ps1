# +──────────────────+
# │  CONFIGURATION   │
# +──────────────────+

# Misc
# $AllowBrowserData = "True"
# $AllowGetDownloadEXEs = "True"
# 


# +──────────────────+
# │  GENERAL  INFO   │
# +──────────────────+
# Begin audit.log
Write-Output "Beginning at`t $([datetime]::Now.ToUniversalTime())`n" |
    Out-File ".\audit.log"

# General information
# This is also being written to the audit.log
Write-Output "------------ General information ------------`n" | Out-File -Append ".\audit.log"

Write-Output "Hostname:`t$((Get-CimInstance -ClassName Win32_ComputerSystem).Name)" | 
    Out-File -Append ".\audit.log"

Write-Output "Username:`t$ENV:USERNAME" | 
    Out-File -Append ".\audit.log"

    # TODO: Omit loopback
Get-NetIPAddress -AddressFamily IPv4 | 
    ForEach-Object 
        -Membername InterfaceAlias, IPAddress | 
    Out-File -Append ".\audit.log"

# Write-Output "IP Address:`t$(Get-NetIPAddress -AddressFamily IPv4)`n" |
    # Out-File -Append ".\audit.log"

