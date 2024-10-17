<# Initiates connections to modules #>
<# Due to issues with Powershell 7 you need to additionally import modules in compatibility mode in order to make them work correctly #>
function Connect-M365SAT
{
	param(
		[string]$Username, 
		[SecureString]$Password, 
		[String[]]$Modules, 
		[string]$Environment
	)

	Import-Module PoShLog
	. $PSScriptRoot\m365connectors\Connect-MicrosoftAzure.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftExchange.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftGraph.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftSecurityCompliance.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftSharepoint.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftTeams.ps1
	
	# Initialize Variables
	[bool]$AzureAuth = $false
	[bool]$GraphAuth = $false
	[bool]$SecurityComplianceAuth = $false
	[bool]$ExchangeAuth = $false
	[bool]$SharepointAuth = $false
	[bool]$TeamsAuth = $false

	if ($PSVersionTable.PSVersion.Major -igt 5)
		{
			Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowershell
		}

	if ($Modules.Contains("All"))
	{
		[Array]$Modules = @("Azure", "Exchange", "Office365", "Sharepoint", "Teams")
	}	
	if (![string]::IsNullOrEmpty($Password))
	{
		#Authentication Username + Password 
		#Store Credentials in Variable
		try
		{
			[securestring]$SecuredPassword = ConvertTo-SecureString -AsPlainText $Password -Force
			[pscredential]$Credential = New-Object System.Management.Automation.PSCredential $UserName, $SecuredPassword
		}
		catch
		{
			Write-ErrorLog "Could Not Convert Credentials!"
		}
	}

	# Make Sure Sharepoint does not get authenticated first, because Sharepoint depends it's name on Microsoft Graph or Microsoft Exchange to get the default domainname automatically.
	switch ($Modules) {
		"Azure" {
			if (![string]::IsNullOrEmpty($Password)){
				$AzureConnection = Invoke-MicrosoftAzureCredentials -Credential $Credential -Environment $Environment
				if (!$AzureConnection)
				{
					break
				}else{
					$AzureAuth = $true
				}
				$GraphOrgName = Invoke-MicrosoftGraphCredentials -Environment $Environment
				if ([string]::IsNullOrEmpty($GraphOrgName))
				{
					break
				}else{
					$GraphAuth = $true
				}
			}else{
				$AzureConnection = Invoke-MicrosoftAzureUsername -Username $UserName -Environment $Environment
				if (!$AzureConnection)
				{
					break
				}else{
					$AzureAuth = $true
				}
				$GraphOrgName = Invoke-MicrosoftGraphUsername -Environment $Environment
				if ([string]::IsNullOrEmpty($GraphOrgName))
				{
					break
				}else{
					$GraphAuth = $true
				}
			}
		}
		"Exchange" {	
			if (![string]::IsNullOrEmpty($Password)){
				if ($GraphAuth -ne $true){
					$GraphOrgName = Invoke-MicrosoftGraphUsername -Environment $Environment
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}else{
						$GraphAuth = $true
					}
				}
				$MSCConnection = Invoke-MicrosoftSecurityComplianceCredentials -Credential $Credential -Environment $Environment
				if (!$MSCConnection)
				{
					break
				}else{
					$SecurityComplianceAuth = $true
				}
				$ExchangeOrgName = Invoke-MicrosoftExchangeCredentials -Credential $Credential -Environment $Environment
				if ([string]::IsNullOrEmpty($ExchangeOrgName))
				{
					break
				}else{
					$ExchangeAuth = $True
				}
			}else{
				if ($GraphAuth -ne $true){
					$GraphOrgName = Invoke-MicrosoftGraphUsername -Environment $Environment
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}else{
						$GraphAuth = $true
					}
				}
				$MSCConnection = Invoke-MicrosoftSecurityComplianceUsername -Username $UserName -Environment $Environment
				if (!$MSCConnection)
				{
					break
				}else{
					$SecurityComplianceAuth = $true
				}
				$ExchangeOrgName = Invoke-MicrosoftExchangeUsername -Username $UserName -Environment $Environment
				if ([string]::IsNullOrEmpty($ExchangeOrgName))
				{
					break
				}else{
					$ExchangeAuth = $True
				}
			}
		}
		"Office365"{
			if ($AzureAuth -ne $true){
				if (![string]::IsNullOrEmpty($Password)){
					$AzureConnection = Invoke-MicrosoftAzureCredentials -Credential $Credential -Environment $Environment
					if (!$AzureConnection)
					{
						break
					}else{
						$AzureAuth = $true
					}
				}else{
					$AzureConnection = Invoke-MicrosoftAzureUsername -Username $UserName -Environment $Environment
					if (!$AzureConnection)
					{
						break
					}else{
						$AzureAuth = $true
					}
				}
			}
			if ($GraphAuth -ne $true){
				if (![string]::IsNullOrEmpty($Password)){
					$GraphOrgName = Invoke-MicrosoftGraphCredentials -Environment $Environment
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}else{
						$GraphAuth = $true
					}
				}else{
					$GraphOrgName = Invoke-MicrosoftGraphUsername -Environment $Environment
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}else{
						$GraphAuth = $true
					}
				}
			}
		}
		"Sharepoint"{
			if (![string]::IsNullOrEmpty($Password)){
				if ($GraphAuth -ne $true){
					$GraphOrgName = Invoke-MicrosoftGraphCredentials -Environment $Environment #Microsoft Sharepoint depends on some the Organization Name provided by Microsoft Graph and cannot be provided by Sharepoint itself.
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}
					else
					{
						$GraphAuth = $true
					}
				}
				$TenantName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
				$Module = Get-Module PnP.PowerShell -ListAvailable
				if ([string]::IsNullOrEmpty($Module)){
					$SharepointConnection = Invoke-MicrosoftSharepointCredentials -TenantName $TenantName -Credential $Credential -Environment $Environment
					if (!$SharepointConnection)
					{
						break
					}else{
						$SharepointAuth = $true
					}
				}
				else
				{
					$SharepointConnection = Invoke-MicrosoftSharepointPnPCredentials -TenantName $TenantName -Credential $Credential -Environment $Environment
					if (!$SharepointConnection)
					{
						break
					}else{
						$SharepointAuth = $true
					}
				}
				
			}else{
				if ($GraphAuth -ne $true){
					$GraphOrgName = Invoke-MicrosoftGraphCredentials -Environment $Environment
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}else{
						$GraphAuth = $true
					}
				}
				$TenantName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
				$Module = Get-Module PnP.PowerShell -ListAvailable
				if ([string]::IsNullOrEmpty($Module)){
					$SharepointConnection = Invoke-MicrosoftSharepointUsername -TenantName $TenantName -Credential $Credential -Environment $Environment
					if (!$SharepointConnection)
					{
						break
					}else{
						$SharepointAuth = $true
					}
				}
				else
				{
					$SharepointConnection = Invoke-MicrosoftSharepointPnPUsername -TenantName $TenantName -Environment $Environment
					if (!$SharepointConnection)
					{
						break
					}else{
						$SharepointAuth = $true
					}
				}
			}
		}
		"Teams"{
			if (![string]::IsNullOrEmpty($Password)){
				if($GraphAuth -ne $true){
					$GraphOrgName = Invoke-MicrosoftGraphCredentials -Environment $Environment #Microsoft Teams does not output the original default domainname, thus we invoke Graph for this as well
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}else{
						$GraphAuth = $true
					}
				}
				$TeamsConnection = Invoke-MicrosoftTeamsCredentials -Credential $Credential -Environment $Environment
				if (!$TeamsConnection)
				{
					break
				}else{
					$TeamsAuth = $true
				}
			}else{
				if($GraphAuth -ne $true){
					$GraphOrgName = Invoke-MicrosoftGraphCredentials -Environment $Environment #Microsoft Teams does not output the original default domainname, thus we invoke Graph for this as well
					if ([string]::IsNullOrEmpty($GraphOrgName))
					{
						break
					}else{
						$GraphAuth = $true
					}
				}
				$TeamsConnection = Invoke-MicrosoftTeamsUsername -Username $UserName -Environment $Environment
				if (!$TeamsConnection)
				{
					break
				}else{
					$TeamsAuth = $true
				}
			}
		}
	}
	if ($null -ne $ExchangeOrgName){
		$ExchangeOrgName = $OrgName
	}else{
		$GraphOrgName = $OrgName
	}
		return $OrgName
}
	