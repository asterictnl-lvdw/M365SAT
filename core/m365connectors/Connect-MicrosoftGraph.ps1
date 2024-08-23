function Invoke-MicrosoftGraphCredentials
{
	param(
		[string]$Environment
	)

	switch ($Environment) {
		"USGovGCCHigh" 
		{ 
			$global:graphURI = 'graph.microsoft.us'
			$GraphEnvironment = 'USGov'
		}
		"USGovDoD" 
		{ 
			$global:graphURI = 'dod-graph.microsoft.us'
			$GraphEnvironment = 'USGovDoD'
		}
		"GermanyCloud" 
		{ 
			$global:graphURI = 'graph.microsoft.com'
			$GraphEnvironment = 'Global'
		}
		"China" 
		{ 
			$global:graphURI = 'microsoftgraph.chinacloudapi.cn'
			$GraphEnvironment = 'China'
		}
		default 
		{ 
			$global:graphURI = 'graph.microsoft.com'
			$GraphEnvironment = 'Global'
		}
	}

	Write-Host "Connecting to Microsoft Graph Powershell..."
	$MSGraph = Connect-MgGraph -Environment $GraphEnvironment -ContextScope Process -Scopes "Directory.Read.All", "RoleManagement.Read.Directory", "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All", "User.Read.All", "Policy.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "Group.Read.All", "UserAuthenticationMethod.Read.All", "GroupMember.Read.All", "Organization.Read.All", "Domain.Read.All", "AccessReview.Read.All", "SecurityEvents.Read.All"
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
	param(
		[string]$Environment
	)

	switch ($Environment) {
		"USGovGCCHigh" 
		{ 
			$global:graphURI = 'graph.microsoft.us'
			$GraphEnvironment = 'USGov'
		}
		"USGovDoD" 
		{ 
			$global:graphURI = 'dod-graph.microsoft.us'
			$GraphEnvironment = 'USGovDoD'
		}
		"GermanyCloud" 
		{ 
			$global:graphURI = 'graph.microsoft.com'
			$GraphEnvironment = 'Global'
		}
		"China" 
		{ 
			$global:graphURI = 'microsoftgraph.chinacloudapi.cn'
			$GraphEnvironment = 'China'
		}
		default 
		{ 
			$global:graphURI = 'graph.microsoft.com'
			$GraphEnvironment = 'Global'
		}
	}

	Write-Host "Connecting to Microsoft Graph Powershell..."
	$MSGraph = Connect-MgGraph -Environment $GraphEnvironment -ContextScope Process -Scopes "Directory.Read.All", "RoleManagement.Read.Directory", "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All", "User.Read.All", "Policy.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "Group.Read.All", "UserAuthenticationMethod.Read.All", "GroupMember.Read.All", "Organization.Read.All", "Domain.Read.All", "AccessReview.Read.All", "SecurityEvents.Read.All"
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
	param(
		[string]$Environment
	)

	switch ($Environment) {
		"USGovGCCHigh" 
		{ 
			$global:graphURI = 'graph.microsoft.us'
			$GraphEnvironment = 'USGov'
		}
		"USGovDoD" 
		{ 
			$global:graphURI = 'dod-graph.microsoft.us'
			$GraphEnvironment = 'USGovDoD'
		}
		"GermanyCloud" 
		{ 
			$global:graphURI = 'graph.microsoft.com'
			$GraphEnvironment = 'Global'
		}
		"China" 
		{ 
			$global:graphURI = 'microsoftgraph.chinacloudapi.cn'
			$GraphEnvironment = 'China'
		}
		default 
		{ 
			$global:graphURI = 'graph.microsoft.com'
			$GraphEnvironment = 'Global'
		}
	}

	Write-Host "Connecting to Microsoft Graph Powershell..."
	$MSGraph = Connect-MgGraph -Environment $GraphEnvironment -ContextScope Process -Scopes "Directory.Read.All", "RoleManagement.Read.Directory", "DeviceManagementServiceConfig.Read.All", "DeviceManagementConfiguration.Read.All", "User.Read.All", "Policy.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "Group.Read.All", "UserAuthenticationMethod.Read.All", "GroupMember.Read.All", "Organization.Read.All", "Domain.Read.All", "AccessReview.Read.All", "SecurityEvents.Read.All"
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