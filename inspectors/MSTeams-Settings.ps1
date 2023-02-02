# This is an MSTeamsSettings Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks various Microsoft Teams Settings
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSTeamsSettings($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMST0009"
		FindingName	     = "Tenant can communicate with external domains, tenants and users via Teams or Skype for Business"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "6.5"
		Description	     = "Tenant Communication should stay internal to avoid information disclosure and information leaks to the public. It is hightly recommended to disallow external domains unless there is a reason that the external users should be communicated with. "
		Remediation	     = "1. Select Admin Centers and Teams. > 2. Under Users select External access > 3. Under Teams and Skype for Business users in external organizations Select Block all external domains > 4. Under Teams accounts not managed by an organization move the slider to Off. > 5. Under Skype users move the slider is to Off. and Save the settings. For PowerShell commands please read the references."
		DefaultValue	 = "AllowedDomains= AllowAllKnownDomains <br /> AllowPublicUsers= True <br /> EnableFederationAccess= True <br /> EnablePublicCloudAccess= True "
		ExpectedValue    = "AllowedDomains= BlockAllExternalDomains <br /> AllowPublicUsers= False <br /> EnableFederationAccess= False <br /> EnablePublicCloudAccess= False"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		PowerShellScript = 'Set-CsExternalAccessPolicy; Set-CsExternalUserCommunicationPolicy; Set-CsTenantFederationConfiguration'
		References	     = @(@{ 'Name' = 'Set up Skype for Business Online'; 'URL' = 'https://docs.microsoft.com/en-us/skypeforbusiness/set-up-skype-for-business-online/set-up-skype-for-business-online' })
	}
}

function Audit-MSTeamsSettings
{
	try
	{
		$MSTeamsSettingsData = @()
		$MSTeamsSettings_1 = Get-CsTenantFederationConfiguration | select Identity, AllowedDomains, AllowPublicUsers
		$MSTeamsSettings_2 = Get-CsExternalAccessPolicy -Identity Global
		if ($MSTeamsSettings_1 -or $MSTeamsSettings_2 -ne $null)
		{
			if ($MSTeamsSettings_1.AllowedDomains -match 'AllowAllKnownDomains' -or $MSTeamsSettings_1.AllowPublicUsers -match 'True' -or $MSTeamsSettings_2.EnableFederationAccess -match 'True' -or $MSTeamsSettings_2.EnablePublicCloudAccess -match 'True')
			{
				$MSTeamsSettingsData += " AllowedDomains: " + $MSTeamsSettings_1.AllowedDomains
				$MSTeamsSettingsData += "`n AllowPublicUsers: " + $MSTeamsSettings_1.AllowPublicUsers
				$MSTeamsSettingsData += " EnableFederationAccess: " + $MSTeamsSettings_2.EnableFederationAccess
				$MSTeamsSettingsData += "`n EnablePublicCloudAccess: " + $MSTeamsSettings_2.EnablePublicCloudAccess
				$endobject = Build-MSTeamsSettings($MSTeamsSettingsData)
				return $endobject
			}
		}
		return $null
	}
	Catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}
return Audit-MSTeamsSettings