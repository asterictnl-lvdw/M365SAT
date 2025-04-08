function Invoke-MicrosoftSecurityComplianceConnection {
    param (
        [Parameter(Mandatory = $false)]
        [SecureString]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$Username,
        [Parameter(Mandatory = $false)]
        [string]$Environment = "default"
    )

    # Map environment names to Security & Compliance environment values
    $environmentMap = @{
        "USGovGCCHigh" = @{
            IPPSEnvironment = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
            AADUri          = 'https://login.microsoftonline.us/common'
        }
        "USGovDoD"     = @{
            IPPSEnvironment = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
            AADUri          = 'https://login.microsoftonline.us/common'
        }
        "GermanyCloud" = @{
            IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
            AADUri          = 'https://login.microsoftonline.com/common'
        }
        "China"        = @{
            IPPSEnvironment = 'https://ps.compliance.protection.partner.outlook.cn/powershell-liveid'
            AADUri          = 'https://login.chinacloudapi.cn/common'
        }
        default        = @{
            IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
            AADUri          = 'https://login.microsoftonline.com/common'
        }
    }

    # Determine the Security & Compliance environment
    $selectedEnv = $environmentMap[$Environment]
    if (-not $selectedEnv) {
        $selectedEnv = $environmentMap["default"]
    }

    $IPPSEnvironment = $selectedEnv.IPPSEnvironment
    $AADUri = $selectedEnv.AADUri

    # Retry logic with a maximum of 3 attempts
    $maxAttempts = 3
    $attempt = 1
    while ($attempt -le $maxAttempts) {
        try {
            Write-Host "Connecting to Microsoft Security & Compliance... (Attempt $attempt of $maxAttempts)"

            # Determine the method of connection based on provided parameters
            if ($Credential) {
                Connect-IPPSSession -DisableWAM -ConnectionUri $IPPSEnvironment -AzureADAuthorizationEndpointUri $AADUri -Credential $Credential -ShowBanner:$false -ErrorAction Stop | Out-Null
            }
            elseif ($Username) {
                Connect-IPPSSession -DisableWAM -ConnectionUri $IPPSEnvironment -AzureADAuthorizationEndpointUri $AADUri -UserPrincipalName $Username -ShowBanner:$false -ErrorAction Stop | Out-Null
            }
            else {
                Connect-IPPSSession -DisableWAM -ConnectionUri $IPPSEnvironment -AzureADAuthorizationEndpointUri $AADUri -ShowBanner:$false -ErrorAction Stop | Out-Null
            }

            # Verify the connection
            $Connection = Get-ConnectionInformation | Where-Object {$_.Name -match "Protection"}
            if (-not [string]::IsNullOrEmpty($Connection)) {
                Write-Host "Connected to Microsoft Security & Compliance!" -ForegroundColor DarkYellow -BackgroundColor Black
                return $true
            }
            else {
                throw "Failed to establish a valid connection with Microsoft Security & Compliance."
            }
        }
        catch {
            Write-Warning "Attempt $attempt failed: $_"
            if ($attempt -ge $maxAttempts) {
                Write-Error "Maximum number of retry attempts reached. Unable to connect to Microsoft Security & Compliance."
                throw $_
            }
            Start-Sleep -Seconds 5  # Wait before retrying
			$attempt++
        }
    }
}