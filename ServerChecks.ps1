#Define lof file location
$LogFile = "C:\ServerChecks.txt"

#Function to write to log file
function Write-Log {
    param([string]$Message,
    [String]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
    Add-Content -Path $LogFile -Value "$(Get-Date -Format "MM/dd/yyyy HH:mm:ss") - $Message"

}

#Write to log file
Write-Log "=== Starting Server Checks ===" "Cyan"

#check powershell version
Write-Log "Checking Powershell Version" "Yellow"
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Log "Powershell version is less than 3.0, Will attempt to update" "Red"

} else {
    Write-Log "Powershell version is greater than 3.0" "Green"
}

# Check .NET Version
Write-Log "Checking .NET Version" "Yellow"
$dotNetVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | Get-ItemProperty -Name Release | Select-Object -ExpandProperty Release
if ($dotNetVersion -lt 528040) {
    Write-Log "NET version is less than 4.0, Need attempt to update" "Red"

} else {
    Write-Log "NET version is greater than 4.0" "Green"
}

# Enable and Configure WinRM
Write-Log "Enabling and Configuring WinRM" "Yellow"
$winrmService = Get-Service WinRM -ErrorAction SilentlyContinue
if (!$winrmService -Or $winrmService.Status -ne "Running") {
    Write-Log "WinRM service is not running, Will attempt to start" "Red"
    WinRM quickconfig -ForegroundColor
} else {
    Write-Log "WinRM service has been started" "Green"
}

#Test WinRM Connectity
Write-Log "Testing WinRm Connectivity" "Yellow"
if (Test-WSMan -ComputerName localhost -ErrorAction SilentlyContinue) {
    Write-Log "WinRm connectivity is working" "Green"
} else {
    Write-Log "WinRM connectivity is not working" "Red"
}

#Enable TLS 1.2 need to work on this
Write-Log "Checking TLS 1.2 configuration..." "Yellow"
$tls12ServerKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
$tls12ClientKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

New-Item -Path $tls12ServerKey -Force | Out-Null
New-Item -Path $tls12ClientKey -Force | Out-Null

Set-ItemProperty -Path $tls12ServerKey -Name "Enabled" -Value 1
Set-ItemProperty -Path $tls12ClientKey -Name "Enabled" -Value 1

#check if TLS1.2 is already included
$enabledProtocols = [Net.ServicePointManager]::SecurityProtocol
if ($enabledProtocols -band [Net.SecurityProtocolType]::Tls12) {
   
    Write-Log "TLS 1.2 has been successfully enabled." "Green"
} else {
    try {
        #enable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol += [Net.ServicePointManager]::Tls12
        Write-Log "TLS 1.2 has been successfully enabled." "Green"
    } catch {
        Write-Log "TLS 1.2 is not enabled." "Red"        
    }

}

# Disk space Check
Write-Log "Checking disk space on all drives..." "Yellow"
$drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } # Fixed drives only
foreach ($drive in $drives) {
    $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
    $freePercentage = [math]::Round(($drive.FreeSpace / $drive.Size) * 100, 2)

    $thresholdGB = 5
    $thresholdPercent = 13

    if ($freeSpaceGB -ge $thresholdGB -or $freePercentage -ge $thresholdPercent) {
        Write-Log "Drive $($drive.DeviceID): Total space: $([math]::Round($drive.Size / 1GB, 2)) GB, Free space: $freeSpaceGB GB ($freePercentage%). Free space is sufficient." "Green"
    } else {
        Write-Log "Drive $($drive.DeviceID): Total space: $([math]::Round($drive.Size / 1GB, 2)) GB, Free space: $freeSpaceGB GB ($freePercentage%). Free space is below the threshold." "Red"
    }
}

Write-Log "=== Ending Server Checks ===" "Cyan"
