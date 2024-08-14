# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Microsoft Authenticator is configured to protect against MFA fatigue
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5234($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5234"
		FindingName	     = "CIS MAz 5.2.3.4 - Not all member users are 'MFA capable'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Multifactor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Users who are not MFA Capable have never registered a strong authentication method for multifactor authentication that is within policy and may not be using MFA. This could be a result of having never signed in, exclusion from a Conditional Access (CA) policy requiring MFA, or a CA policy does not exist. Reviewing this list of users will help identify possible lapses in policy or procedure"
		Remediation	     = "Implement a CA policy to require all users to use MFA and include all users"
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails/fromNav/Identity'
		DefaultValue	 = "IsMFACapable: false if there is no CA policy enforcing MFA"
		ExpectedValue    = "IsMFACapable: true"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'View applied Conditional Access policies in Microsoft Entra sign-in logs'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/how-to-view-applied-conditional-access-policies' },
		@{ 'Name' = 'Authentication Methods Activity'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity' })
	}
	return $inspectorobject
}

function Audit-CISMAz5234
{
	try
	{	
		$Check = Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "IsMfaCapable eq false and UserType eq 'Member'" | Select-Object UserPrincipalName, IsMfaCapable,IsAdmin


		if ($Check.Count -igt 0)
		{
			$Check | Format-Table -AutoSize | Out-File "$path\CISMAz5234-NotCapableMFAUsers.txt"
			Build-CISMAz5234("file://$path\CISMAz5234-NotCapableMFAUsers.txt")
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

return Audit-CISMAz5234