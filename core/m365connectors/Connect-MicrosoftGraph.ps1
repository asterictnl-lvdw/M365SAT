function Invoke-MicrosoftGraphCredentials($Credentials)
{
	Write-Host "Connecting to Microsoft Graph Powershell..."
	$MSGraph = Connect-MgGraph -ContextScope Process -Scopes "AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All", "IdentityProvider.Read.All", "Organization.Read.All", "Securityevents.Read.All", "ThreatIndicators.Read.All", "SecurityActions.Read.All", "User.Read.All", "UserAuthenticationMethod.Read.All", "MailboxSettings.Read", "Policy.Read.All", "Group.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All","AccessReview.Read.All"
	if ((Get-MgContext) -ne $null)
	{
		Write-Host "Connected to Microsoft Graph Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
		#Select-MgProfile -Name beta
		$OrgName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
		return $OrgName
	}
	else
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Graph Powershell' -ErrorRecord $_
		return $null
	}
}

function Invoke-MicrosoftGraphUsername
{
	Write-Host "Connecting to Microsoft Graph Powershell..."
	$MSGraph = Connect-MgGraph -ContextScope Process -Scopes "AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All", "IdentityProvider.Read.All", "Organization.Read.All", "Securityevents.Read.All", "ThreatIndicators.Read.All", "SecurityActions.Read.All", "User.Read.All", "UserAuthenticationMethod.Read.All", "MailboxSettings.Read", "Policy.Read.All", "Group.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All","AccessReview.Read.All"
	if ((Get-MgContext) -ne $null)
	{
		Write-Host "Connected to Microsoft Graph Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
		#Select-MgProfile -Name beta
		$OrgName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
		return $OrgName
	}
	else
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Graph Powershell' -ErrorRecord $_
		return $null
	}
}

function Invoke-MicrosoftGraphLite
{
	Write-Host "Connecting to Microsoft Graph Powershell..."
	$MSGraph = Connect-MgGraph -ContextScope Process -Scopes "AuditLog.Read.All", "Policy.Read.All", "Directory.Read.All", "IdentityProvider.Read.All", "Organization.Read.All", "Securityevents.Read.All", "ThreatIndicators.Read.All", "SecurityActions.Read.All", "User.Read.All", "UserAuthenticationMethod.Read.All", "MailboxSettings.Read", "Policy.Read.All", "Group.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All","AccessReview.Read.All"
	if ((Get-MgContext) -ne $null)
	{
		Write-Host "Connected to Microsoft Graph Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
		#Select-MgProfile -Name beta
		$OrgName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
		return $OrgName
	}
	else
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Graph Powershell' -ErrorRecord $_
		return $null
	}
}