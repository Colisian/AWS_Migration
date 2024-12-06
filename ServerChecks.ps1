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
    Write-Log "Powershell version is less than 3.0, Will attempt o update" "Red"

} else {
    Write-Log "Powershell version is greater than 3.0" "Green"
}

# Check .NET Version
Write-Log "Checking .NET Version" "Yellow"
$dotNetVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' | Get-ItemPropertyValue -Name Release | Select-Object -ExpandProperty Release
if ($dotNetVersion -lt 528040) {
    Write-Log "NET version is less than 4.9.0, Will attempt to update" "Red"

} else {
    Write-Log "NET version is greater than 4.9.0" "Green"
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

#Enable TLS 1.2
Write-Log "Enabling TLS 1.2" "Yellow"
if([Net.ServicePointManager]::SecurityProtocol -notcontains "Tls12") {
    
}
