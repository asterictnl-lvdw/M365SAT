# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure That No Custom Subscription Administrator Roles Exist
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1220($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1220"
		FindingName	     = "CIS Az 1.22 - Custom Subscription Administrator Roles Exist"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Classic subscription admin roles offer basic access management and include Account Administrator, Service Administrator, and Co-Administrators. It is recommended the least necessary permissions be given initially. Permissions can be added as needed by the account holder. This ensures the account holder cannot perform actions which were not intended."
		Remediation	     = "Use the Azure CloudShell Script to enable Security Defaults on Microsoft Azure Active Directory"
		PowerShellScript = 'az role definition delete --name <role name>'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Add or change Azure subscription administrators'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/add-change-subscription-administrator' },
			@{ 'Name' = 'Introducing security defaults'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/introducing-security-defaults/ba-p/1061414' },
		@{ 'Name' = 'IM-2: Protect identity and authentication systems'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-2-protect-identity-and-authentication-systems' })
	}
	return $inspectorobject
}

function Audit-CISAz1220
{
	try
	{
		$CustomSubscriptionAdministratorRoleList = @()
		# Actual Script
		$CustomSubscriptionAdministratorRoles = Get-AzRoleDefinition | Where-Object { ($_.IsCustom -eq $true) -and ($_.Actions.contains('*')) }
		
		if ($CustomSubscriptionAdministratorRoles.Count -igt 0)
		{
			foreach ($Role in $CustomSubscriptionAdministratorRoles)
			{
				$CustomSubscriptionAdministratorRoleList += $Role.Name
			}
			$finalobject = Build-CISAz1220($CustomSubscriptionAdministratorRoleList)
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
return Audit-CISAz1220