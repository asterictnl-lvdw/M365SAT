# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that an exclusionary Geographic Access Policy is considered
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz222($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz222"
		FindingName	     = "CIS Az 2.2.2 - No exclusionary Geographic Access Policy considered"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Conditional Access, when used as a deny list for the tenant or subscription, is able to prevent ingress or egress of traffic to countries that are outside of the scope of interest (e.g.: customers, suppliers) or jurisdiction of an organization. This is an effective way to prevent unnecessary and long-lasting exposure to international threats such as APTs."
		Remediation	     = "Please use the link described in the PowerShell Script to create a ConditionalAccessPolicy"
		PowerShellScript = 'New-AzureADMSConditionalAccessPolicy -Name "Policy Name" -State <enabled|disabled> -Conditions $conditions -GrantControls $controls'
		DefaultValue	 = "null"
		ExpectedValue    = "A policy"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Conditional Access: Block access by location'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-location' },
			@{ 'Name' = 'What is Conditional Access report-only mode?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' })
	}
	return $inspectorobject
}

function Audit-CISAz222
{
	try
	{
		# Actual Script
		# Actual Script
		$Violation = @()
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.Conditions.Locations.IncludeLocations.Count -igt 0) -and ($_.GrantControls.BuiltInControls -eq "block")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Geographic Access!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled') {
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Geographic Access is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz222GeoAccessPolicies.txt"
				}
			}
		}
		
		# Validation
		if ($affectedpolicy.Count -igt 0)
		{
			$affectedpolicy | Format-Table -AutoSize | Out-File "$path\CISAz222GeoAccessPolicies.txt"
			$finalobject = Build-CISAz222($affectedpolicy)
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
return Audit-CISAz222