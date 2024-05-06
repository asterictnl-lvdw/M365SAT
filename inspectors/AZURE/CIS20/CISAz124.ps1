# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz124($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz124"
		FindingName	     = "CIS Az 1.2.4 - No Multi-factor Authentication Policy Exists for Users"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Enabling multi-factor authentication is a recommended setting to limit the potential of accounts being compromised and limiting access to authenticated personnel."
		Remediation	     = "Please use the link described in the PowerShell Script to create an additional ConditionalAccessPolicy"
		PowerShellScript = 'https://hub.steampipe.io/mods/turbot/azure_compliance/controls/control.CISAz_v200_1_2_4?context=benchmark.CISAz_v200/benchmark.CISAz_v200_1/benchmark.CISAz_v200_1_2'
		DefaultValue	 = "null"
		ExpectedValue    = "A policy"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Common Conditional Access policy: Require MFA for administrators'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa' },
			@{ 'Name' = 'Manage emergency access accounts in Azure AD'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/security-emergency-access' },
			@{ 'Name' = 'Troubleshooting Conditional Access using the What If tool'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/troubleshoot-conditional-access-what-if' },
			@{ 'Name' = 'Conditional Access insights and reporting'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-insights-reporting' },
			@{ 'Name' = 'Plan a Conditional Access deployment'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/plan-conditional-access' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' })
	}
	return $inspectorobject
}

function Audit-CISAz124
{
	try
	{
		# Actual Script
		$GeoAccessPolicy = Get-MgIdentityConditionalAccessPolicy
		$affectedpolicy = @()
		foreach ($policy in $conditionalAccessPolicies)
		{
			$policy | Select-Object @{ N = 'Policy ID'; E = { $policy.id } }, @{ N = 'Policy State'; E = { $policy.id } }, @{ N = "Included Locations"; E = { $policy.Conditions.Locations.IncludeLocations } }, @{ N = "Excluded Locations"; E = { $policy.Conditions.Locations.ExcludeLocations } }, @{ N = "BuiltIn GrantControls"; E = { $policy.GrantControls.BuiltInControls } }
			if ($policy.GrantControls.BuiltInControls -notcontains "mfa")
			{
				#Skips policies that do not contain MFA
				continue
			}
			else
			{
				if ($policy.State -contains 'disabled')
				{
					$affectedpolicy += "$($policy.id):  $($policy.State)"
				}
			}
		}
		
		# Validation
		if ($affectedpolicy.Count -igt 0)
		{
			$affectedpolicy | Format-Table -AutoSize | Out-File "$path\CISAz124MFAPolicies.txt"
			$finalobject = Build-CISAz124($affectedpolicy)
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
return Audit-CISAz124