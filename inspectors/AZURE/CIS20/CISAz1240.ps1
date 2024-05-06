# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That No Custom Subscription Administrator Roles Exist
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1240($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1240"
		FindingName	     = "CIS Az 1.24 - No Custom Role is Assigned Permissions for Administering Resource Locks"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Given the resource lock functionality is outside of standard Role Based Access Control(RBAC), it would be prudent to create a resource lock administrator role to prevent inadvertent unlocking of resources."
		Remediation	     = "Use the PowerShell Script in the URL to create a new Resource Lock Administrator"
		PowerShellScript = 'https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.CISAz_v200_1_24?context=benchmark.CISAz_v200/benchmark.CISAz_v200_1'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Azure custom roles'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles' },
			@{ 'Name' = 'Quickstart: Check access for a user to Azure resources'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access' })
	}
	return $inspectorobject
}

function Audit-CISAz1240
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
			$finalobject = Build-CISAz1240($ResourceLockAdministratorsList)
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
return Audit-CISAz1240