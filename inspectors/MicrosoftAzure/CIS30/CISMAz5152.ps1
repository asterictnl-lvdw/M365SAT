# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure user consent to apps accessing company data on their behalf is not allowed
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5152($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5152"
		FindingName	     = "CISMAz 5.1.5.2 - User consent to apps accessing company data on their behalf is allowed!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Attackers commonly use custom applications to trick users into granting them access to company data. Disabling future user consent operations setting mitigates this risk, and helps to reduce the threat-surface. If user consent is disabled previous consent grants will still be honored but all future consent operations must be performed by an administrator."
		Remediation	     = "Use the PowerShell Script disable user consent for Non-Admin Users."
		PowerShellScript = '$params = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = @() } }; Update-MgPolicyAuthorizationPolicy -BodyParameter $params'
		DefaultValue	 = "Null"
		ExpectedValue    = "Null"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Security defaults in Azure AD'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults' },
			@{ 'Name' = 'Introducing security defaults'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/introducing-security-defaults/ba-p/1061414' },
			@{ 'Name' = 'IM-2: Protect identity and authentication systems'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-2-protect-identity-and-authentication-systems' })
	}
	return $inspectorobject
}

function Audit-CISMAz5152
{
	try
	{
		# Actual Script
		$UserConsentSetting = (Get-MgPolicyAuthorizationPolicy -Property "defaultUserRolePermissions").DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
		
		# Validation
		if (-not [string]::IsNullOrEmpty($UserConsentSetting))
		{
			$finalobject = Build-CISMAz5152($UserConsentSetting)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMAz5152