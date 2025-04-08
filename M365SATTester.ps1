#Requires -Version 5.1

<#
    Configuration Section: Modify these parameters as needed.
    These values will be used when calling the ExecuteM365SAT function.
#>
$ScriptConfig = @{
    OutPath          = "/home/example/m365sat/out"                  # Change this path based on your OS (e.g., "C:\Out" for Windows)
    Username         = "example@example.org"                        # Replace with your username
    EnvironmentType  = 'M365','AZURE'                               # Specify the environment type (e.g., M365, AZURE, or All)
    Modules          = "All"                                        # Specify the modules to include (e.g., "All" or specific modules (e.g. 'Azure', 'Exchange', 'Office365', 'Sharepoint', 'Teams' ))
    LicenseMode      = "E3"                                         # Specify the license mode (e.g., "E3", "E5" or "All")
    LicenseLevel     = "All"                                        # Specify the license level (e.g. "L1", "L2" or "All")
    ReportType       = "HTML"                                       # Specify the report type (e.g., "CSV", "HTML")
    AllowLogging     = [switch]::Present                            # Enable logging if needed (true/false)
    LocalMode        = [switch]::Present                            # Enable local mode if needed (true/false)
    SkipChecks       = [switch]::Present                            # Skip checks if needed (true/false)
}

function ExecuteM365SAT {
    <#
        Executes the M365SAT report generation using the parameters from $ScriptConfig.
        The Import-Module and Remove-Module commands ensure proper module handling.
    #>
    param (
        [string]$OutPath,
        [string]$Username,
        [string[]]$EnvironmentType,
        [string[]]$Modules,
        [string]$LicenseMode,
        [string]$LicenseLevel,
        [string]$ReportType,
        [switch]$AllowLogging,
        [switch]$LocalMode,
        [switch]$SkipChecks
    )

    Import-Module .\M365SAT.psd1 -ErrorAction Stop
    try {
        Get-M365SATReport @PSBoundParameters
    } finally {
        Remove-Module M365SAT -Force
    }
}

function Get-PSEnvironmentInfo {
    <#
        Detects the operating system and PowerShell version.
        Returns an object with two properties:
        - PowerShellVersion: Major version of PowerShell (e.g., 5 or 7)
        - OperatingSystem: Detected OS (Windows, Linux, macOS, or Unknown)
    #>
    $psVersion = $PSVersionTable.PSVersion.Major
    $OS = "Unknown"

    if ($IsWindows -or $env:OS -eq 'Windows_NT' -or [System.Environment]::OSVersion.Platform -eq 'Win32NT' -or $psVersion -eq 5) {
        $OS = "Windows"
    } elseif ($IsLinux -or [System.Environment]::OSVersion.Platform -eq 'Unix') {
        $OS = "Linux"
    } elseif ($IsMacOS -or [System.Environment]::OSVersion.Platform -eq 'MacOSX') {
        $OS = "macOS"
    }
    return [PSCustomObject]@{
        PowerShellVersion = $psVersion
        OperatingSystem   = $OS
    }
}

function CheckAdminPrivileges {
    <#
        Checks if the script is running with administrative privileges on Windows.
        If not, it attempts to elevate the script using RunAs.
        For Linux and macOS, it directly executes the M365SAT function.
    #>
    $OSInfo = Get-PSEnvironmentInfo
    Write-Host "Your OS: $($OSInfo.OperatingSystem)" -ForegroundColor Cyan

    if ($OSInfo.OperatingSystem -eq 'Windows') {
        Write-Host "[+] Your OS is: $($OSInfo.OperatingSystem) running PowerShell: $($OSInfo.PowerShellVersion)"
        Write-Host "[...] Checking if the script is running as Administrator"
        $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $IsAdmin) {
            Write-Warning "[!] Program needs Administrator Rights! Trying to Elevate to Admin..."
            Start-Process powershell -Verb runas -ArgumentList "-NoExit -c cd '$pwd'; .\M365SATTester.ps1"
            return
        }
    } elseif ($OSInfo.OperatingSystem -in 'Linux', 'macOS') {
        Write-Host "[+] Your OS is: $($OSInfo.OperatingSystem) running PowerShell: $($OSInfo.PowerShellVersion)" -ForegroundColor Green
    } else {
        Write-Host "Could not identify the Operating System!" -ForegroundColor Red
        return
    }

    # Execute the M365SAT function with the configured parameters
    ExecuteM365SAT @ScriptConfig
}

# Entry point of the script
CheckAdminPrivileges