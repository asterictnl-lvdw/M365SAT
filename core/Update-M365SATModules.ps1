<# 
    Updates all required M365 modules to their latest versions.
    Ensures TLS v1.2 is enabled, checks for module updates, and handles Linux-specific requirements.
#>

function Update-M365SATModules {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Environment = "Global"
    )

    # Ensure TLS v1.2 is enabled for secure connections
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord

    # Ensure PSGallery is a trusted repository
    if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
        Write-Host "PSGallery repository set to trusted."
    }

    # Define the list of modules to check and update
    $ModuleList = @(
        "MicrosoftTeams",
        "Az",
        "ExchangeOnlineManagement",
        "Microsoft.Graph",
        "Microsoft.Graph.Beta"
    )

    # Add PnP.PowerShell for PowerShell versions > 5
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        $ModuleList += "PnP.PowerShell"
    } else {
        $ModuleList += "Microsoft.Online.SharePoint.PowerShell"
    }

    # Handle Linux-specific requirements
    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Unix) {
        # Check if PSWSMan is installed under the sudo user
        if (-not (Get-InstalledModule -Name PSWSMan -ErrorAction SilentlyContinue)) {
            Write-Host "PSWSMan is not installed. Installing it under the sudo user..."
			Install-Module -Name PSWSMan -Scope AllUsers
            sudo pwsh -Command 'Install-WSMan'
            if ($?) {
                Write-Host "PSWSMan installation completed successfully."
                Write-Host "Please re-run this script to continue installing other modules."
                return
            } else {
                Write-Warning "Failed to install PSWSMan. Please ensure you have sufficient privileges."
                return
            }
        }
    }

    # Check and update each module
    foreach ($module in $ModuleList) {
        try {
            # Get installed version
            $installedVersion = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version
            if ($null -eq $installedVersion) {
                Write-Host "Module '$module' is not installed."
                $install = Read-Host "Do you want to install module '$module'? (Y/N)"
                if ($install.ToLower() -eq 'y') {
                    Install-Module -Name $module -Scope CurrentUser -Force -Confirm:$false
                    Write-Host "Module '$module' has been installed."
                } else {
                    Write-Host "Skipping installation of module '$module'."
                }
                continue
            }

            # Get online version
            $onlineVersion = Find-Module -Name $module | Select-Object -ExpandProperty Version

            # Compare versions
            if ([version]$installedVersion -ge [version]$onlineVersion) {
                Write-Host "Module '$module' is up-to-date (Installed: $installedVersion, Online: $onlineVersion)."
            } else {
                Write-Host "Module '$module' is outdated (Installed: $installedVersion, Online: $onlineVersion)."
                $update = Read-Host "Do you want to update module '$module'? (Y/N)"
                if ($update.ToLower() -eq 'y') {
                    Update-Module -Name $module -Force -Confirm:$false
                    Write-Host "Module '$module' has been updated to version $onlineVersion."
                } else {
                    Write-Host "Skipping update of module '$module'."
                }
            }
        } catch {
            Write-Warning "An error occurred while processing module '$module': $_"
        }
    }
}

function Check-PowerShellGetVersion {
    <#
        Ensures PowerShellGet is updated to the latest version.
        If not installed, prompts the user to install it.
    #>
    $PowerShellGetVersion = Get-InstalledModule -Name "PowerShellGet" -ErrorAction SilentlyContinue
    if ($null -eq $PowerShellGetVersion) {
        Write-Host "`nPowerShellGet is not installed." -ForegroundColor Red
        $install = Read-Host "Would you like to install PowerShellGet now? (Y|N)"
        if ($install.ToLower() -eq 'y') {
            Write-Host "Installing NuGet package provider..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            Write-Host "Installing PowerShellGet..."
            Install-Module "PowerShellGet" -Scope CurrentUser -Force -Confirm:$false -AllowClobber
        }
    } else {
        Write-Host "PowerShellGet is already installed (Version: $($PowerShellGetVersion.Version))."
    }
}
