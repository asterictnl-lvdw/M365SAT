# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Multi-factor Authentication is Required for Risky Sign-ins
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz227($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz227"
		FindingName	     = "CIS Az 2.2.7 - No Multi-factor Authentication Policy Exists for Azure Service Management API"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Administrative access to the Windows Azure Service Management API should be secured with a higher level of scrutiny to authenticating mechanisms. Enabling multi-factor authentication is recommended to reduce the potential for abuse of Administrative actions, and to prevent intruders or compromised admin credentials from changing administrative settings."
		Remediation	     = "Please use the link described in the PowerShell Script to create an additional ConditionalAccessPolicy"
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "null"
		ExpectedValue    = "A policy"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Conditional Access: Users, groups, and workload identities'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups' },
			@{ 'Name' = 'Common Conditional Access policy: Require MFA for Azure management'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-azure-management' },
			@{ 'Name' = 'Windows Azure Service Management API'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#windows-azure-service-management-api' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' })
	}
	return $inspectorobject
}

function Audit-CISAz227
{
	try
	{
		# Actual Script
		$Violation = @()
		#Since the authflow function is in beta we must call the beta module to retrieve the settings
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "797f4846-ba00-4fd7-ba43-dac1f8f63013") -and ($_.GrantControls.BuiltInControls -eq "mfa")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for Azure Management API!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled')
				{
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy for Azure Management API is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz227-MFAPoliciesForAzureManagementAPI.txt"
				}
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISAz227($Violation)
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
return Audit-CISAz227