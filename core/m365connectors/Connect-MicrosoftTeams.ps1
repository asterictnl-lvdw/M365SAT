function Invoke-MicrosoftTeamsConnection {
    param (
        [Parameter(Mandatory = $false)]
        [SecureString]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$Username,
        [Parameter(Mandatory = $false)]
        [string]$Environment = "default"
    )

    # Map environment names to Teams environment values
    $environmentMap = @{
        "USGovGCCHigh" = @{
            EnvironmentName = "TeamsGCCH"
        }
        "USGovDoD"     = @{
            EnvironmentName = "TeamsDoD"
        }
        "GermanyCloud" = @{
            EnvironmentName = $null
        }
        "China"        = @{
            EnvironmentName = "TeamsChina"
        }
        default        = @{
            EnvironmentName = $null
        }
    }

    # Determine the Teams environment
    $selectedEnv = $environmentMap[$Environment]
    if (-not $selectedEnv) {
        $selectedEnv = $environmentMap["default"]
    }

    $TmsEnvironmentName = $selectedEnv.EnvironmentName

    # Retry logic with a maximum of 3 attempts
    $maxAttempts = 3
    $attempt = 1
    while ($attempt -le $maxAttempts) {
        try {
            Write-Host "Connecting to Microsoft Teams... (Attempt $attempt of $maxAttempts)"

            # Determine the method of connection based on provided parameters
            if ($Credential) {
                if ($null -ne $TmsEnvironmentName) {
                    Connect-MicrosoftTeams -TeamsEnvironmentName $TmsEnvironmentName -Credential $Credential -ErrorAction Stop | Out-Null
                }
                else {
                    Connect-MicrosoftTeams -Credential $Credential -ErrorAction Stop | Out-Null
                }
            }
            elseif ($Username) {
                if ($null -ne $TmsEnvironmentName) {
                    Connect-MicrosoftTeams -TeamsEnvironmentName $TmsEnvironmentName -ErrorAction Stop | Out-Null
                }
                else {
                    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
                }
            }
            else {
                if ($null -ne $TmsEnvironmentName) {
                    Connect-MicrosoftTeams -TeamsEnvironmentName $TmsEnvironmentName -ErrorAction Stop | Out-Null
                }
                else {
                    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
                }
            }

            # Verify the connection
            if ($null -ne (Get-CsTenant)) {
                Write-Host "Connected to Microsoft Teams!" -ForegroundColor DarkYellow -BackgroundColor Black
                return $true
            }
            else {
                throw "Failed to establish a valid context with Microsoft Teams."
            }
        }
        catch {
            Write-Warning "Attempt $attempt failed: $_"
            if ($attempt -ge $maxAttempts) {
                Write-Error "Maximum number of retry attempts reached. Unable to connect to Microsoft Teams."
                throw $_
            }
            Start-Sleep -Seconds 5  # Wait before retrying
			$attempt++
        }
    }
}