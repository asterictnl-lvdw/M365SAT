# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz225($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz225"
		FindingName	     = "CIS Az 2.2.5 - No Multi-factor Authentication Policy Exists for All Users"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Enabling multi-factor authentication is a recommended setting to limit the potential of accounts being compromised and limiting access to authenticated personnel."
		Remediation	     = "Please use the link described in the PowerShell Script to create an additional ConditionalAccessPolicy"
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "null"
		ExpectedValue    = "A policy"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Common Conditional Access policy: Require MFA for all users'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' },
			@{ 'Name' = 'Troubleshooting Conditional Access using the What If tool'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access-what-if' },
			@{ 'Name' = 'Conditional Access insights and reporting'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' })
	}
	return $inspectorobject
}

function Audit-CISAz225
{
	try
	{
		# Actual Script
		$Violation = @()
		#Since the authflow function is in beta we must call the beta module to retrieve the settings
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.GrantControls.BuiltInControls -eq "mfa")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for All Users!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled') {
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy for All Users is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz225-MFAPoliciesForAllUsers.txt"
				}
			}
		}
		
		# Validation

		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISAz225($Violation)
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
return Audit-CISAz225