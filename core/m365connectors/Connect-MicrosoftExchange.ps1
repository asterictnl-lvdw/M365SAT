function Invoke-MicrosoftExchangeCredentials($Credential)
{
	try
	{
		Write-Host "Connecting to Microsoft Exchange..."
		Connect-ExchangeOnline -Credential $Credential -ShowBanner:$false -ErrorAction Stop
		if ((Get-ConnectionInformation) -ne $null)
		{
			$OrgName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
			Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $OrgName
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftExchangeUsername($Username)
{
	try
	{
		Write-Host "Connecting to Microsoft Exchange..."
		Connect-ExchangeOnline -UserPrincipalName $Username -ShowBanner:$false
		if ((Get-ConnectionInformation) -ne $null)
		{
			$OrgName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
			Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $OrgName
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftExchangeLite
{
	try
	{
		Write-Host "Connecting to Microsoft Exchange..."
		Connect-ExchangeOnline -ShowBanner:$false
		if ((Get-ConnectionInformation) -ne $null)
		{
			$OrgName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
			Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $OrgName
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
		return $false
	}
	
}