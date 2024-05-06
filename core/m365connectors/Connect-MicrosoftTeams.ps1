function Invoke-MicrosoftTeamsCredentials($Credential)
{
	try
	{
		Write-Host "Connecting to Microsoft Teams Powershell..."
		$Team = Connect-MicrosoftTeams -Credential $Credential -ErrorAction Stop
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

function Invoke-MicrosoftTeamsUsername($Username)
{
	try
	{
		Write-Host "Connecting to Microsoft Teams Powershell..."
		$Team = Connect-MicrosoftTeams -ErrorAction Stop
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
	try
	{
		Write-Host "Connecting to Microsoft Teams Powershell..."
		$Team = Connect-MicrosoftTeams -ErrorAction Stop
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