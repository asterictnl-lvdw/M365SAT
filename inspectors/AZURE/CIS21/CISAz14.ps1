# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Allow users to remember multi-factor authentication on devices they trust' is Disabled (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISAz114($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz14"
		FindingName	     = "CIS Az 1.1.4 - Allow users to remember multi-factor authentication on devices they trust is Enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "4"
		Description	     = "Remembering Multi-Factor Authentication (MFA) for devices and browsers allows users to have the option to bypass MFA for a set number of days after performing a successful sign-in using MFA. This can enhance usability by minimizing the number of times a user may need to perform two-step verification on the same device. However, if an account or device is compromised, remembering MFA for trusted devices may affect security. Hence, it is recommended that users not be allowed to bypass MFA."
		Remediation	     = "Check via the link "
		PowerShellScript = 'https://account.activedirectory.windowsazure.com/UserManagement/MfaSettings.aspx'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "4"
		Likelihood	     = "1"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure Microsoft Entra multifactor authentication settings'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-mfasettings#remember-multi-factor-authentication-for-devices-that-users-trust' },
			@{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' })
	}
	return $inspectorobject
}

function Audit-CISAz114
{
	try
	{
		
		$finalobject = Build-CISAz114("Check the value here: https://account.activedirectory.windowsazure.com/UserManagement/MfaSettings.aspx")
		return $finalobject
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz114