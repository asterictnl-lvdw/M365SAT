# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure third party integrated applications are not allowed
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz220($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz220"
		FindingName	     = "CIS MAz 2.2 - Third party integrated applications are allowed!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Third party integrated applications connection to services should be disabled, unless there is a very clear value and robust security controls are in place. While there are legitimate uses, attackers can grant access from breached accounts to third party applications to exfiltrate data from your tenancy without having to maintain the breached account."
		Remediation	     = "Manually change it here: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/AdminConsentSettings "
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings'
		DefaultValue	 = "AllowedToCreateApps: True"
		ExpectedValue    = "AllowedToCreateApps: False"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'How and why applications are added to Azure AD'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-how-applications-are-added' })
	}
	return $inspectorobject
}

function Audit-CISMAz220
{
	try
	{
		# Actual Script
		$AuthPolicy = Get-MgPolicyAuthorizationPolicy
		
		
		# Validation
		if ($AuthPolicy.DefaultUserRolePermissions.AllowedToCreateApps -eq $true)
		{
			$finalobject = Build-CISMAz220("AllowedToCreateApps: $($AuthPolicy.DefaultUserRolePermissions.AllowedToCreateApps)")
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
return Audit-CISMAz220