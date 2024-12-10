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

# create a local admin account
Write-Log "Creating Local Admin Account" "Yellow"
try {
    #username and password
    $username = "trianz"
    $password = ConvertTo-SecureString "NeededForTri@nz!" -AsPlainText -Force

    #check if the account already exists
    if (Get-LocalUser -Name $username -ErrorAction SilentlyContinue) {
        Write-Log "Local admin account exists" "Green"
    } else {
        #create the local admin account
        New-LocalUser -Name $username -Password $password -Fullname "Trianz admin" -Description "Local admin account for trianz" -UserMayNotChangePassword -PasswordNeverExpires -AccountNeverExpires
        
        #add to administrtators group
        Add-LocalGroupMember -Group "Administrators" -Member $username

        Write-Log "Local admin account created" "Green"
    }
} catch {
    Write-Log "Failed to create local admin account" "Red"
}

#check Powershell Execution Policy
Write-Log "Checking Powershell Execution Policy" "Yellow"
try {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
    Write-Log "Powershell Execution Policy has been set to Unrestricted" "Green"
}
catch {
    Write-Log "Failed to set Powershell Execution Policy to Unrestricted" "Red"
}


#check powershell version
Write-Log "Checking Powershell Version" "Yellow"
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Log "Powershell version is less than 3.0, Will attempt to update" "Red"

} else {
    Write-Log "Powershell version is greater than 3.0" "Green"
}

# Check .NET Version
Write-Log "Checking .NET Version" "Yellow"
$dotNetVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Release

#Determine the installed version of .NET
$dotNetVersionReport = Switch ($dotNetVersion) {
    { $_ -ge 528040 } { "Installed .NET Version: 4.8 or later"; break }
    { $_ -ge 461808 } { "Installed .NET Version: 4.7.2"; break }
    { $_ -ge 461308 } { "Installed .NET Version: 4.7.1"; break }
    { $_ -ge 460798 } { "Installed .NET Version: 4.7"; break }
    { $_ -ge 394802 } { "Installed .NET Version: 4.6.2"; break }
    { $_ -ge 394254 } { "Installed .NET Version: 4.6.1"; break }
    { $_ -ge 393295 } { "Installed .NET Version: 4.6 or later"; break }
    { $_ -lt 393295 } { "Installed .NET Version is below 4.0. Update required!"; break }
    Default { "Version not detected or unsupported version found." }
}

Write-Log $dotNetVersionReport "Green"


if ($dotNetVersion -lt 393295) {
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

#Checking winRM on HTTPS
try {
    $httpsListener = Get-ChildItem -Path WSMan:\localhost\Listener\ | Where-Object { $_.Transport -eq "HTTPS" }
    if ($httpsListener) {
        $listenerDetails = $httpsListener | Select-Object -Property Address, Transport, Port, CertificateThumbprint
        Write-Log "WinRM HTTPS listener is enabled" "Green"
        Write-Log "Listener Details:" "Green"
        $listenerDetails | ForEach-Object {
            Write-Log "Address: $($_.Address)"
            Write-Log "Transport: $($_.Transport)"
            Write-Log "Port: $($_.Port)"
            Write-Log "Certificate Thumbprint: $($_.CertificateThumbprint)"
        }
    } else {
        Write-Log "WinRM HTTPS Listener is NOT configured" "Red"
    }
} catch {
    Write-Log "Error while checking WinRM HTTPS Listener. Error: $_" "Red"

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
 