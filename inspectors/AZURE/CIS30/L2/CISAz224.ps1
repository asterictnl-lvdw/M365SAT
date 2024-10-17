# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure 3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that A Multi-factor Authentication Policy Exists for Administrative Groups
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz224($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz224"
		FindingName	     = "CIS Az 2.2.4 - No Multi-factor Authentication Policy Exists for Administrative Groups"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "20"
		Description	     = "Enabling multi-factor authentication is a recommended setting to limit the use of Administrative accounts to authenticated personnel."
		Remediation	     = "Please use the link described in the PowerShell Script to create an additional ConditionalAccessPolicy"
		PowerShellScript = ''
		DefaultValue	 = "null"
		ExpectedValue    = "A policy"
		ReturnedValue    = "$findings"
		Impact		     = "4"
		Likelihood	     = "5"
		RiskRating	     = "Critical"
		Priority		 = "Critical"
		References	     = @(@{ 'Name' = 'Common Conditional Access policy: Require MFA for administrators'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-admin-mfa' },
			@{ 'Name' = 'Manage emergency access accounts in Azure AD'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' },
			@{ 'Name' = 'Troubleshooting Conditional Access using the What If tool'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access-what-if' },
			@{ 'Name' = 'Conditional Access insights and reporting'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting' },
			@{ 'Name' = 'Plan a Conditional Access deployment'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/plan-conditional-access' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' })
	}
	return $inspectorobject
}

function Audit-CISAz224
{
	try
	{
		# Actual Script
		$Violation = @()

		#Get all administrative roles
		$Roles = (Get-MgRoleManagementDirectoryRoleDefinition | Where-Object {$_.DisplayName -match "Administrator"}).Id | Sort-Object

		# We use a count check to see if a CA-Policy has all the same amount of Administrator roles to get the correct policy
		$Policies = (Get-MgIdentityConditionalAccessPolicy | Where-Object {($_.Conditions.Users.IncludeRoles.Count -eq $Roles.Count)})

		# In case we have multiple policies:
		foreach ($Policy in $Policies){
			$PolicyRoles = $Policy.Conditions.Users.IncludeRoles | Sort-Object

			# We do a object comparison here as we want to see if all roles are included within the Policy Roles array and output the result as a boolean
			if (($Roles | Compare-Object $PolicyRoles) -as [bool]){
				$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy Exists for Administrative Groups does not contain all administrative groups!"
				($Roles | Compare-Object $PolicyRoles) | Format-Table -AutoSize | Out-File "$path\CISAz224MFAPolicies.txt"
			}
			# We do a check if the full configuration is existing 
			if( -not ($Policy |  Where-Object { ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.GrantControls.BuiltInControls -eq "mfa")})){
				$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy Exists for Administrative Groups is not correctly configured!"
			}
		}

		#We do a regular check for the policy if the policy is existing at all if the first foreach loop is skipped. 
		
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for Administrative Groups"
		}
		else
		{
			#We do a check if the policy is disabled
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled') {
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy Exists for Administrative Groups is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz224MFAPolicies.txt"
				}
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$Violation | Format-Table -AutoSize | Out-File -Append "$path\CISAz224MFAPolicies.txt"
			$finalobject = Build-CISAz224($Violation)
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
return Audit-CISAz224