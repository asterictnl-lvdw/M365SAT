function Invoke-MicrosoftTeamsCredentials
{
	param(
		[System.Object]$Credential,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH -Credential $Credential -ErrorAction Stop" 
			}
			"USGovDoD" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsDoD -Credential $Credential  -ErrorAction Stop"
			}
			"GermanyCloud" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -Credential $Credential -ErrorAction Stop"
			}
			"China" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsChina -Credential $Credential -ErrorAction Stop"
			}
			default 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -Credential $Credential"
			}
		}

		Write-Host "Connecting to Microsoft Teams Powershell..."
		$Team = Invoke-Expression $TmsEnvironment
		if (-not [string]::IsNullOrEmpty($Team))
		{
			Write-Host "Connected to Microsoft Teams Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Teams Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Teams Powershell' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftTeamsUsername
{
	param(
		[string]$Username,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH" 
			}
			"USGovDoD" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsDoD"
			}
			"GermanyCloud" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams"
			}
			"China" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsChina"
			}
			default 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams"
			}
		}

		Write-Host "Connecting to Microsoft Teams Powershell..."
		$Team = Invoke-Expression $TmsEnvironment
		if (-not [string]::IsNullOrEmpty($Team))
		{
			Write-Host "Connected to Microsoft Teams Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Teams Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Teams Powershell' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftTeamsLite
{
	param(
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsGCCH" 
			}
			"USGovDoD" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsDoD"
			}
			"GermanyCloud" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams"
			}
			"China" 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams -TeamsEnvironmentName TeamsChina"
			}
			default 
			{ 
				$TmsEnvironment = "Connect-MicrosoftTeams"
			}
		}

		Write-Host "Connecting to Microsoft Teams Powershell..."
		$Team = Invoke-Expression $TmsEnvironment
		if (-not [string]::IsNullOrEmpty($Team))
		{
			Write-Host "Connected to Microsoft Teams Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Teams Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Teams Powershell' -ErrorRecord $_
		return $false
	}
	
}