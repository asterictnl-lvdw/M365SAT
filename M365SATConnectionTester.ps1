<#
    M365SAT Connection Tester v1.0 ~ @Karmakstylez (C) 2025
    Simplified to ensure proper module checks, OS detection, and connection testing.
#>

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

function Check-M365SATModules {
    <#
        Checks if all required M365 modules are installed.
        If not, prompts the user to install them or terminates the script if a required module is missing.
    #>
    Write-Warning "[?] Checking Installed Modules..."
    $Modules = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Graph", "Microsoft.Graph.Beta", "PoShLog")
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        $Modules += "PnP.PowerShell"
    } else {
        $Modules += "Microsoft.Online.SharePoint.PowerShell"
    }

    foreach ($module in $Modules) {
        if (-not (Get-InstalledModule -Name $module -ErrorAction SilentlyContinue)) {
            Write-Host "`n$module is not installed." -ForegroundColor Red
            $install = Read-Host "Do you want to install module '$module'? (Y/N)"
            if ($install.ToLower() -eq 'y') {
                try {
                    Write-Host "Installing module '$module'..."
                    Install-Module -Name $module -Scope CurrentUser -Force -Confirm:$false -AllowClobber
                    Write-Host "$module has been installed successfully." -ForegroundColor Green
                } catch {
                    Write-Error "Failed to install module '$module': $_"
                    throw "The module '$module' is required for M365SAT to work. Please resolve the issue and try again."
                }
            } else {
                throw "The module '$module' is required for M365SAT to work. Installation aborted."
            }
        } else {
            Write-Host "[+] $module is installed." -ForegroundColor Green
        }
    }
    Write-Host "All required modules are installed successfully!" -ForegroundColor Green
}

function Disconnect-Modules {
    <#
        Disconnects from all connected modules.
    #>
    try {
        Disconnect-AzAccount | Out-Null
        Invoke-MgBetaInvalidateAllUserRefreshToken -UserId (Get-MgContext).Account
        Disconnect-MgGraph | Out-Null
        Disconnect-ExchangeOnline -Confirm:$false
        if ($PSVersionTable.PSVersion.Major -gt 5) {
            Disconnect-PnPOnline | Out-Null
        } else {
            Disconnect-SPOService | Out-Null
        }
        Disconnect-MicrosoftTeams | Out-Null
        Write-Host "Disconnected from all modules." -ForegroundColor Cyan
    } catch {
        Write-Warning "Error during disconnection: $_"
    }
}

function Test-ModuleConnection {
    param (
        [string]$ModuleName,
        [scriptblock]$ConnectCommand,
        [scriptblock]$ValidationCommand
    )
    try {
        Write-Host "Connecting to $ModuleName..." -ForegroundColor Yellow
        & $ConnectCommand
        if (& $ValidationCommand) {
            Write-Host "Successfully connected to $ModuleName." -ForegroundColor Green
            return $true
        } else {
            Write-Host "Failed to validate connection to $ModuleName." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "Failed to connect to $ModuleName : $_" -ForegroundColor Red
        return $false
    }
}

function RunConnectionTests {
    param (
        [string]$Username
    )
    $SuccessList = @()
    $FailureList = @()

    # This is the correct order for testing the modules!
    $ConnectionTests = @(
        @{
            Name = "Microsoft Teams"
            Connect = { Connect-MicrosoftTeams}
            Validate = { $null -ne (Get-CsTenant) }
        },
        @{
            Name = "Microsoft Azure"
            Connect = { Connect-AzAccount -AccountId $Username -Environment "AzureCloud" }
            Validate = { $null -ne (Get-AzContext) }
        },
        @{
            Name = "Microsoft Graph"
            Connect = { Connect-MgGraph -Scopes "Directory.Read.All", "RoleManagement.Read.Directory" }
            Validate = { $null -ne (Get-MgContext) }
        },
        @{
            Name = "Exchange Online"
            Connect = { Connect-ExchangeOnline -UserPrincipalName $Username -ShowBanner:$false }
            Validate = { $null -ne (Get-ConnectionInformation) }
        },
        @{
            Name = "Microsoft Security Compliance"
            Connect = { Connect-IPPSSession -UserPrincipalName $Username -ShowBanner:$false }
            Validate = { $null -ne (Get-PolicyConfig) }
        },
        @{
            Name = "SharePoint"
            Connect = {
                if ($PSVersionTable.PSVersion.Major -gt 5) {
                    Connect-PnPOnline -Url "https://$((Get-MgOrganization).VerifiedDomains | Where-Object { $_.Name -like "*.onmicrosoft.com" }).Name-admin.sharepoint.com" -Interactive
                } else {
                    Connect-SPOService -Credential $Username -Url "https://$((Get-MgOrganization).VerifiedDomains | Where-Object { $_.Name -like "*.onmicrosoft.com" }).Name-admin.sharepoint.com"
                }
            }
            Validate = { $null -ne (Get-SPOTenant) }
        }
    )

    # Run connection tests
    foreach ($test in $ConnectionTests) {
        if (Test-ModuleConnection -ModuleName $test.Name -ConnectCommand $test.Connect -ValidationCommand $test.Validate) {
            $SuccessList += $test.Name
        } else {
            $FailureList += $test.Name
        }
    }

    # Display results
    Write-Host "`nConnection Test Results:" -ForegroundColor Cyan
    Write-Host "Successfully Connected: $($SuccessList -join ', ')" -ForegroundColor Green
    Write-Host "Failed to Connect: $($FailureList -join ', ')" -ForegroundColor Red

    # Disconnect from all modules
    Disconnect-Modules
}

# Main Script Execution
Write-Host "M365SAT Connection Tester v1.0 ~ @Karmakstylez (C) 2025" -ForegroundColor Yellow
$OSInfo = Get-PSEnvironmentInfo
Write-Host "Detected OS: $($OSInfo.OperatingSystem), PowerShell Version: $($OSInfo.PowerShellVersion)" -ForegroundColor Cyan

# Check modules
Check-M365SATModules

# Run connection tests
RunConnectionTests -Username "example@example.org"