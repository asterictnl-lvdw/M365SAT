# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Microsoft Authenticator is configured to protect against MFA fatigue
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5231($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5231"
		FindingName	     = "CIS MAz 5.2.3.1 - Microsoft Authenticator is not configured to protect against MFA fatigue"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "As the use of strong authentication has become more widespread, attackers have started to exploit the tendency of users to experience 'MFA fatigue.' This occurs when users are repeatedly asked to provide additional forms of identification, leading them to eventually approve requests without fully verifying the source. To counteract this, number matching can be employed to ensure the security of the authentication process. With this method, users are prompted to confirm a number displayed on their original device and enter it into the device being used for MFA. Additionally, other information such as geolocation and application details are displayed to enhance the end user's awareness. Among these 3 options, number matching provides the strongest net security gain."
		Remediation	     = "Navigate to Microsoft Entra and select Microsoft Authenticator. Review the settings and set it to all_users and enable the first 3 options in the Configure section."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods'
		DefaultValue	 = "Enabled for tenants >2022, Disabled for tenants <2022"
		ExpectedValue    = "From 2023 if not manually assigned it would be enabled if Microsoft manages the setting."
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Protecting authentication methods in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-default-enablement' },
		@{ 'Name' = 'Defend your users from MFA fatigue attacks'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-blog/defend-your-users-from-mfa-fatigue-attacks/ba-p/2365677' },
		@{ 'Name' = 'How number matching works in multifactor authentication push notifications for Authenticator - Authentication methods policy'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match' })
	}
	return $inspectorobject
}

function Audit-CISMAz5231
{
	try
	{
		$IncorrectMFASettings = @()
		$MFASettings = Invoke-MgGraphRequest -Method GET https://graph.microsoft.com/beta/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator
		
		if ($MFASettings.includeTargets.targetType -ne "group" -or $MFASettings.includeTargets.id -ne "all_users")
		{
			$IncorrectMFASettings += "targetType: $($MFASettings.includeTargets.targetType)"
			$IncorrectMFASettings += "id: $($MFASettings.includeTargets.id)"
		}
		if ($MFASettings.featureSettings.displayAppInformationRequiredState.state -ne "enabled" -or $MFASettings.featureSettings.displayLocationInformationRequiredState.includeTarget.id -ne "all_users")
		{
			$IncorrectMFASettings += "displayAppInformationRequiredState: $($MFASettings.featureSettings.displayAppInformationRequiredState.state) targetid: $($MFASettings.featureSettings.displayLocationInformationRequiredState.includeTarget.id)"
		}
		if ($MFASettings.featureSettings.displayLocationInformationRequiredState.state -ne "enabled" -or $MFASettings.featureSettings.displayLocationInformationRequiredState.includeTarget.id -ne "all_users")
		{
			$IncorrectMFASettings += "displayLocationInformationRequiredState: $($MFASettings.featureSettings.displayLocationInformationRequiredState.state) targetid: $($MFASettings.featureSettings.displayLocationInformationRequiredState.includeTarget.id)"
		}
		if ($MFASettings.featureSettings.numberMatchingRequiredState.state -ne "enabled" -or $MFASettings.featureSettings.numberMatchingRequiredState.includeTarget.id -ne "all_users")
		{
			$IncorrectMFASettings += "numberMatchingRequiredState: $($MFASettings.featureSettings.numberMatchingRequiredState.state) targetid: $($MFASettings.featureSettings.numberMatchingRequiredState.includeTarget.id)"
		}
		if ($IncorrectMFASettings.Count -ne 0)
		{
			$IncorrectMFASettings | Format-Table -AutoSize | Out-File "$path\CISMAz5231-MFASettings.txt"
			Build-CISMAz5231($IncorrectMFASettings)
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

return Audit-CISMAz5231