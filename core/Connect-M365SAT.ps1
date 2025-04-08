function Connect-M365SAT {
    param (
        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [SecureString]$Password,

        [Parameter(Mandatory = $true)]
        [String[]]$Modules,

        [Parameter(Mandatory = $false)]
        [string]$Environment = "default"
    )

    # Import required modules for logging and connectors
    Import-Module PoShLog
    . $PSScriptRoot\m365connectors\Connect-MicrosoftAzure.ps1
    . $PSScriptRoot\m365connectors\Connect-MicrosoftExchange.ps1
    . $PSScriptRoot\m365connectors\Connect-MicrosoftGraph.ps1
    . $PSScriptRoot\m365connectors\Connect-MicrosoftSecurityCompliance.ps1
    . $PSScriptRoot\m365connectors\Connect-MicrosoftSharepoint.ps1
    . $PSScriptRoot\m365connectors\Connect-MicrosoftTeams.ps1

    # Initialize variables
    $OrgName = $null
    $Credential = $null

    # Disable WAM and LoginExperienceV2 for Azure module compatibility
    Update-AzConfig -EnableLoginByWam $false -LoginExperienceV2 'Off'

    # Import SharePoint module in PowerShell 7 (fallback for PnP.PowerShell)
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowerShell
    }

    # Handle credentials
    if (![string]::IsNullOrEmpty($Password)) {
        try {
            $Credential = New-Object System.Management.Automation.PSCredential ($Username, $Password)
        }
        catch {
            Write-ErrorLog "Could not convert credentials!"
            $Credential = $null
        }
    }

    # Ensure 'All' is expanded to all modules
    if ($Modules.Contains("All")) {
        $Modules = @("Teams", "Azure", "Graph", "Exchange", "SecurityCompliance", "Sharepoint")
    }

    # Authentication flow: Teams -> Azure -> Graph -> Exchange -> SecurityCompliance -> Sharepoint
    foreach ($module in $Modules) {
        switch ($module) {
            "Teams" {
                # Authenticate Teams (requires Graph for organization name)
                if (-not $OrgName) {
                    $OrgName = Invoke-MicrosoftGraphConnection -Credential $Credential -Environment $Environment
                    if ([string]::IsNullOrEmpty($OrgName)) {
                        throw "Failed to authenticate Microsoft Graph, which is required for Teams."
                    }
                }
                $teamsAuth = Invoke-MicrosoftTeamsConnection -Username $Username -Credential $Credential -Environment $Environment
                if (-not $teamsAuth) {
                    throw "Failed to authenticate Microsoft Teams."
                }
            }

            "Azure" {
                # Authenticate Azure
                $azureAuth = Invoke-MicrosoftAzureConnection -Username $Username -Credential $Credential -Environment $Environment
                if (-not $azureAuth) {
                    throw "Failed to authenticate Microsoft Azure."
                }
            }

            "Graph" {
                # Authenticate Graph (if not already authenticated via Teams)
                if ([string]::IsNullOrEmpty($OrgName)) {
                    $OrgName = Invoke-MicrosoftGraphConnection -Credential $Credential -Environment $Environment
                    if ([string]::IsNullOrEmpty($OrgName)) {
                        throw "Failed to authenticate Microsoft Graph."
                    }
                }
            }

            "Exchange" {
                # Authenticate Exchange (requires Graph for organization name)
                if ([string]::IsNullOrEmpty($OrgName)) {
                    $OrgName = Invoke-MicrosoftGraphConnection -Credential $Credential -Environment $Environment
                    if ([string]::IsNullOrEmpty($OrgName)) {
                        throw "Failed to authenticate Microsoft Graph, which is required for Exchange."
                    }
                }
                $exchangeAuth = Invoke-MicrosoftExchangeConnection -Username $Username -Credential $Credential -Environment $Environment
                if (-not $exchangeAuth) {
                    throw "Failed to authenticate Microsoft Exchange."
                }
            }

            "SecurityCompliance" {
                # Authenticate Security & Compliance (requires Graph for organization name)
                if ([string]::IsNullOrEmpty($OrgName)) {
                    $OrgName = Invoke-MicrosoftGraphConnection -Credential $Credential -Environment $Environment
                    if ([string]::IsNullOrEmpty($OrgName)) {
                        throw "Failed to authenticate Microsoft Graph, which is required for Security & Compliance."
                    }
                }
                $securityComplianceAuth = Invoke-MicrosoftSecurityComplianceConnection -Username $Username -Credential $Credential -Environment $Environment
                if (-not $securityComplianceAuth) {
                    throw "Failed to authenticate Microsoft Security & Compliance."
                }
            }

            "Sharepoint" {
                # Authenticate SharePoint (requires Graph for organization name)
                if ([string]::IsNullOrEmpty($OrgName)) {
                    $OrgName = Invoke-MicrosoftGraphConnection -Credential $Credential -Environment $Environment
                    if ([string]::IsNullOrEmpty($OrgName)) {
                        throw "Failed to authenticate Microsoft Graph, which is required for SharePoint."
                    }
                }
                $Module = Get-Module PnP.PowerShell -ListAvailable
				if ([string]::IsNullOrEmpty($Module))
                {
                    $sharepointAuth = Invoke-MicrosoftSharepointSPOServiceConnection -TenantName $OrgName -Credential $Credential -Environment $Environment
                }
                else
                {
                    $sharepointAuth = Invoke-MicrosoftSharepointPnPConnection -TenantName $OrgName -Credential $Credential -Environment $Environment
                }
                if (-not $sharepointAuth) {
                    throw "Failed to authenticate Microsoft SharePoint."
                }
            }
        }
    }

    # Ensure at least one valid OrgName is returned (from Graph or Exchange)
    if ([string]::IsNullOrEmpty($OrgName)) {
        throw "Failed to retrieve a valid organization name from any module."
    }

    return $OrgName
}