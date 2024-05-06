# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Enable Azure AD Identity Protection user risk policies
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMAz5226($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5226"
		FindingName	     = "CIS MAz 5.2.2.6 - Verify if you have an Azure AD Identity Proteciton user risk policy enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "With the user risk policy turned on, Azure AD detects the probability that a user account has been compromised. Administrators can configure a user risk conditional access policy to automatically respond to a specific user risk level."
		Remediation	     = "Unfortunately we cannot accurately detect if a user risk risk policy is enabled. If you have a user risk policy. Please verify if the settings are configured correctly."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Correctly Configured Policy"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'How To: Give risk feedback in Azure AD Identity Protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-risk-feedback' },
		@{ 'Name' = 'What are risk detections?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks' })
	}
	return $inspectorobject
}

function Audit-CISMAz5226
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Select-Object * | Where-Object { $_.DisplayName -like "*user risk*" }
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5226-UserRiskConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -eq "disabled")
				{
					$Violation += $Policy.Id
				}
				else
				{
					#Multiple Checks to determine if the policy is not configured correctly
					$PolicyInfo = Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.Id)"
					if ([string]::IsNullOrEmpty($PolicyInfo.conditions.userRiskLevels) -or -not [string]::IsNullOrEmpty($PolicyInfo.conditions.signInRiskLevels))
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.conditions.applications.includeApplications -ne "All" -or $PolicyInfo.conditions.users.includeUsers -ne "All")
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.grantControls.builtInControls -ne "mfa")
					{
						$Violation += $Policy.Id
					}
				}
				
			}
		}
		else
		{
			$Violation += "No Conditional Access Policy Configured!"
		}
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISMAz5226($Violation)
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
return Audit-CISMAz5226