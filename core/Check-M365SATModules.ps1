function Check-M365SATModules {
    <#
        Checks if all required M365 modules are installed.
        If not, prompts the user to install them or terminates the script if a required module is missing.
    #>

    Write-Warning "[?] Checking Installed Modules..."

    # Define the list of required modules
    $Modules = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Graph", "Microsoft.Graph.Beta", "PoShLog")
    $moduleinstalled = 0

    # Add PnP.PowerShell for PowerShell versions > 5, otherwise use Microsoft.Online.SharePoint.PowerShell
    if ($PSVersionTable.PSVersion.Major -gt 5) {
        $Modules += "PnP.PowerShell"
    } else {
        $Modules += "Microsoft.Online.SharePoint.PowerShell"
    }

    # Ensure all required modules are installed
    while ($true) {
        foreach ($module in $Modules) {
            # Check if the module is installed
            $installedModule = Get-InstalledModule -Name $module -ErrorAction SilentlyContinue
            if (-not $installedModule) {
                Write-Host "`n$module is not installed." -ForegroundColor Red

                # Prompt the user to install the missing module
                do {
                    $install = (Read-Host "Do you want to install module '$module'? (Y/N)").ToLower()
                } while ($install -notin @('y', 'n'))

                if ($install -eq 'y') {
                    try {
                        Write-Host "Installing module '$module'..."
                        Install-Module -Name $module -Scope CurrentUser -Force -Confirm:$false -AllowClobber
                        Write-Host "$module has been installed successfully." -ForegroundColor Green
                        $moduleinstalled++
                    } catch {
                        Write-Error "Failed to install module '$module': $_"
                        throw "The module '$module' is required for M365SAT to work. Please resolve the issue and try again."
                    }
                } else {
                    throw "The module '$module' is required for M365SAT to work. Installation aborted."
                }
            } else {
                Write-Host "[+] $module version $($installedModule.Version) is installed." -ForegroundColor Green
                $moduleinstalled++
            }
        }

        # Verify if all modules are installed
        if ($moduleinstalled -eq 7) {
            Write-Host "All required modules are installed successfully!" -ForegroundColor Green
            break
        } else {
            Write-Warning "Some modules are still missing. Rechecking..."
        }
    }

}