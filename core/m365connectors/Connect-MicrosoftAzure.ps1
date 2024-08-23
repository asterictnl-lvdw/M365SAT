function Invoke-MicrosoftAzureCredentials
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
				$AzEnvironment = 'AzureUSGovernment' 
			}
			"USGovDoD" 
			{ 
				$AzEnvironment = 'AzureUSGovernment' 
			}
			"GermanyCloud" 
			{ 
				$AzEnvironment = 'AzureGermanCloud' 
			}
			"China" 
			{ 
				$AzEnvironment = 'AzureChinaCloud' 
			}
			default 
			{ 
				$AzEnvironment = 'AzureCloud'
			}
		}

		Write-Host "Connecting to Microsoft Azure Powershell..."
		Connect-AzAccount -Environment $AzEnvironment -Credential $Credential -ErrorAction Stop
		if ((Get-AzContext) -ne $null)
		{
			Write-Host "Connected to Microsoft Azure Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Azure Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Azure Powershell' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftAzureUsername
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
				$AzEnvironment = 'AzureUSGovernment' 
			}
			"USGovDoD" 
			{ 
				$AzEnvironment = 'AzureUSGovernment' 
			}
			"GermanyCloud" 
			{ 
				$AzEnvironment = 'AzureGermanCloud' 
			}
			"China" 
			{ 
				$AzEnvironment = 'AzureChinaCloud' 
			}
			default 
			{ 
				$AzEnvironment = 'AzureCloud'
			}
		}
		Write-Host "Connecting to Microsoft Azure Powershell..."
		Connect-AzAccount -AccountId $Username -Environment $AzEnvironment -ErrorAction Stop
		if ((Get-AzContext) -ne $null)
		{
			Write-Host "Connected to Microsoft Azure Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Azure Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Azure Powershell' -ErrorRecord $_
		return $false
	}
}

function Invoke-MicrosoftAzureLite
{
	param(
		[string]$Environment
	)
	
	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$AzEnvironment = 'AzureUSGovernment' 
			}
			"USGovDoD" 
			{ 
				$AzEnvironment = 'AzureUSGovernment' 
			}
			"GermanyCloud" 
			{ 
				$AzEnvironment = 'AzureGermanCloud' 
			}
			"China" 
			{ 
				$AzEnvironment = 'AzureChinaCloud' 
			}
			default 
			{ 
				$AzEnvironment = 'AzureCloud'
			}
		}

		Write-Host "Connecting to Microsoft Azure Powershell..."
		Connect-AzAccount -Environment $AzEnvironment -ErrorAction Stop | Out-Null
		if ((Get-AzContext) -ne $null)
		{
			Write-Host "Connected to Microsoft Azure Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Azure Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Azure Powershell' -ErrorRecord $_
		return $false
	}
	
}