function Invoke-MicrosoftAzureCredentials($Credential)
{
	try
	{
		Write-Host "Connecting to Microsoft Azure Powershell..."
		Connect-AzAccount -Credential $Credential -ErrorAction Stop
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

function Invoke-MicrosoftAzureUsername($Username)
{
	try
	{
		Write-Host "Connecting to Microsoft Azure Powershell..."
		Connect-AzAccount -AccountId $Username -ErrorAction Stop | Out-Null
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
	try
	{
		Write-Host "Connecting to Microsoft Azure Powershell..."
		Connect-AzAccount -ErrorAction Stop | Out-Null
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