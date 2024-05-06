# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose:  Ensure Multifactor Authentication is Required to access Microsoft Admin Portals
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz127($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz127"
		FindingName	     = "CIS Az 1.2.7 - Multifactor Authentication is not Required to access Microsoft Admin Portals"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Administrative Portals for Microsoft Azure should be secured with a higher level of scrutiny to authenticating mechanisms. Enabling multifactor authentication is recommended to reduce the potential for abuse of Administrative actions, and to prevent intruders or compromised admin credentials from changing administrative settings."
		Remediation	     = "Create an Conditional Access Policy to enable MFA For Admin Portals"
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "null"
		ExpectedValue    = "A policy"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Conditional Access: Users, groups, and workload identities'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups' },
			@{ 'Name' = 'Common Conditional Access policy: Require multifactor authentication for admins accessing Microsoft admin portals'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-mfa-admin-portals' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' })
	}
	return $inspectorobject
}

function Audit-CISAz127
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
			$affectedpolicy | Format-Table -AutoSize | Out-File "$path\CISAz127MFAPolicies.txt"
			$finalobject = Build-CISAz127($affectedpolicy)
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
return Audit-CISAz127