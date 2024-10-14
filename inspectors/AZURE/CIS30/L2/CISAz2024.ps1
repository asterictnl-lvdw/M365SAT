# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That No Custom Subscription Administrator Roles Exist
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2024($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2024"
		FindingName	     = "CIS Az 2.24 - No Custom Role is Assigned Permissions for Administering Resource Locks"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Given the resource lock functionality is outside of standard Role Based Access Control(RBAC), it would be prudent to create a resource lock administrator role to prevent inadvertent unlocking of resources."
		Remediation	     = "New-AzRoleDefinition -Role $role"
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Azure custom roles'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles' },
			@{ 'Name' = 'Quickstart: Check access for a user to Azure resources'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access' },
			@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
			@{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
			@{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategyment'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
			@{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' },
			@{ 'Name' = 'PA-7: Follow just enough administration (least privilege) principle'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle' })
	}
	return $inspectorobject
}

function Audit-CISAz2024
{
	try
	{
		$ResourceLockAdministratorsList = @()
		# Actual Script
		$ResourceLockAdministrators = Get-AzRoleDefinition | Where-Object { ($_.IsCustom -eq $true) -and ($_.Name -like '*Resource Lock*') }
		
		if ($ResourceLockAdministrators.Count -igt 0)
		{
			foreach ($Role in $ResourceLockAdministrators)
			{
				$ResourceLockAdministratorsList += $Role.Name
			}
			$finalobject = Build-CISAz2024($ResourceLockAdministratorsList)
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
return Audit-CISAz2024