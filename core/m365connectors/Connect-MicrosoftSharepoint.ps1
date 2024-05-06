function Invoke-MicrosoftSharepointCredentials($tenantname, $Credential)
{
	try
	{
		Write-Host "Connecting to Microsoft Sharepoint Powershell..."
		Connect-SPOService -Url "https://$tenantname-admin.sharepoint.com" -Credential $Credential -ErrorAction Stop
		if ((Get-SPOTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft Sharepoint Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftSharepointUsername($tenantname)
{
	try
	{
		Write-Host "Connecting to Microsoft Sharepoint Powershell..."
		Connect-SPOService -Url "https://$tenantname-admin.sharepoint.com" -ErrorAction Stop
		if ((Get-SPOTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft Sharepoint Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftSharepointLite($tenantname)
{
	try
	{
		Write-Host "Connecting to Microsoft Sharepoint Powershell..."
		Connect-SPOService -Url "https://$tenantname-admin.sharepoint.com" -ErrorAction Stop
		if ((Get-SPOTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft Sharepoint Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
		return $false
	}
	
}