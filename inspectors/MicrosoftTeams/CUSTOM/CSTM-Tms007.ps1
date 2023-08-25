# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Teams
# Purpose: Ensure External Domain Communication Policies are existing
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Tms007($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms007"
		FindingName	     = "CSTM-Tms007 - Tenant can communicate with external domains, tenants and users via Teams or Skype for Business"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "3"
		Description	     = "Tenant Communication should stay internal to avoid information disclosure and information leaks to the public. It is hightly recommended to disallow external domains unless there is a reason that the external users should be communicated with. "
		Remediation	     = "1. Select Admin Centers and Teams. > 2. Under Users select External access > 3. Under Teams and Skype for Business users in external organizations Select Block all external domains > 4. Under Teams accounts not managed by an organization move the slider to Off. > 5. Under Skype users move the slider is to Off. and Save the settings. For PowerShell commands please read the references."
		DefaultValue	 = "AllowedDomains= AllowAllKnownDomains <br /> AllowPublicUsers= True <br /> EnableFederationAccess= True <br /> EnablePublicCloudAccess= True "
		ExpectedValue    = "AllowedDomains= BlockAllExternalDomains <br /> AllowPublicUsers= False <br /> EnableFederationAccess= False <br /> EnablePublicCloudAccess= False"
		ReturnedValue    = $findings
		Impact		     = "1"
		Likelihood	     = "3"
		RiskRating	     = "Low"
		Priority		 = "Low"
		PowerShellScript = 'Set-CsExternalAccessPolicy; Set-CsExternalUserCommunicationPolicy; Set-CsTenantFederationConfiguration'
		References	     = @(@{ 'Name' = 'Set up Skype for Business Online'; 'URL' = 'https://docs.microsoft.com/en-us/skypeforbusiness/set-up-skype-for-business-online/set-up-skype-for-business-online' })
	}
}

function Audit-CSTM-Tms007
{
	try
	{
		$MSTeamsSettingsData = @()
		$MSTeamsSettings_1 = Get-CsTenantFederationConfiguration | Select-Object Identity, AllowedDomains, AllowPublicUsers
		$MSTeamsSettings_2 = Get-CsExternalAccessPolicy -Identity Global
		if ($MSTeamsSettings_1 -or $MSTeamsSettings_2 -ne $null)
		{
			if ($MSTeamsSettings_1.AllowedDomains -match 'AllowAllKnownDomains' -or $MSTeamsSettings_1.AllowPublicUsers -match 'True' -or $MSTeamsSettings_2.EnableFederationAccess -match 'True' -or $MSTeamsSettings_2.EnablePublicCloudAccess -match 'True')
			{
				$MSTeamsSettingsData += " AllowedDomains: " + $MSTeamsSettings_1.AllowedDomains
				$MSTeamsSettingsData += "`n AllowPublicUsers: " + $MSTeamsSettings_1.AllowPublicUsers
				$MSTeamsSettingsData += " EnableFederationAccess: " + $MSTeamsSettings_2.EnableFederationAccess
				$MSTeamsSettingsData += "`n EnablePublicCloudAccess: " + $MSTeamsSettings_2.EnablePublicCloudAccess
				$endobject = Build-CSTM-Tms007($MSTeamsSettingsData)
				return $endobject
			}
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Tms007