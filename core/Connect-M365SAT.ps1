<# Initiates connections to modules #>
<# Due to issues with Powershell 7 you need to additionally import modules in compatibility mode in order to make them work correctly #>
function Connect-M365SAT
{
	Import-Module PoShLog
	. $PSScriptRoot\m365connectors\Connect-MicrosoftAzure.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftExchange.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftGraph.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftSecurityCompliance.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftSharepoint.ps1
	. $PSScriptRoot\m365connectors\Connect-MicrosoftTeams.ps1
	
	
	
	if (![string]::IsNullOrEmpty($Username) -and ![string]::IsNullOrEmpty($Password))
	{
		#Authentication Username + Password 
		#Store Credentials in Variable
		try
		{
			$SecuredPassword = ConvertTo-SecureString -AsPlainText $Password -Force
			$Credential = New-Object System.Management.Automation.PSCredential $UserName, $SecuredPassword
		}
		catch
		{
			Write-ErrorLog "Could Not Convert Credentials!"
		}
		$bool1 = Invoke-MicrosoftAzureCredentials($Credential)
		if (!$bool1)
		{
			break
		}
		$OrgName = Invoke-MicrosoftGraphCredentials
		if ([string]::IsNullOrEmpty($OrgName))
		{
			break
		}
		$bool2 = Invoke-MicrosoftSecurityComplianceCredentials($Credential)
		if (!$bool2)
		{
			break
		}
		$bool3 = Invoke-MicrosoftExchangeCredentials($Credential)
		if (!$bool3)
		{
			break
		}
		$bool4 = Invoke-MicrosoftSharepointCredentials($OrgName, $Credential)
		if (!$bool4)
		{
			break
		}
		$bool5 = Invoke-MicrosoftTeamsCredentials($Credential)
		if (!$bool5)
		{
			break
		}
		return $OrgName
	}
	elseif (![string]::IsNullOrEmpty($Username))
	{
		$bool1 = Invoke-MicrosoftAzureUsername($Username)
		if (!$bool1)
		{
			break
		}
		$OrgName = Invoke-MicrosoftGraphUsername
		if ([string]::IsNullOrEmpty($OrgName))
		{
			break
		}
		$bool2 = Invoke-MicrosoftSecurityComplianceUsername($Username)
		if (!$bool2)
		{
			break
		}
		$bool3 = Invoke-MicrosoftExchangeUsername($Username)
		if (!$bool3)
		{
			break
		}
		$bool4 = Invoke-MicrosoftSharepointUsername($OrgName)
		if (!$bool4)
		{
			break
		}
		$bool5 = Invoke-MicrosoftTeamsUsername($Username)
		if (!$bool5)
		{
			break
		}
		return $OrgName
	}
	else
	{
		$bool1 = Invoke-MicrosoftAzureLite
		if (!$bool1)
		{
			break
		}
		$OrgName = Invoke-MicrosoftGraphLite
		if ([string]::IsNullOrEmpty($OrgName))
		{
			break
		}
		$bool2 = Invoke-MicrosoftSecurityComplianceLite
		if (!$bool2)
		{
			break
		}
		$bool3 = Invoke-MicrosoftExchangeLite
		if (!$bool3)
		{
			break
		}
		$bool4 = Invoke-MicrosoftSharepointLite($OrgName)
		if (!$bool4)
		{
			break
		}
		$bool5 = Invoke-MicrosoftTeamsLite
		if (!$bool5)
		{
			break
		}
		return $OrgName
	}
	
}