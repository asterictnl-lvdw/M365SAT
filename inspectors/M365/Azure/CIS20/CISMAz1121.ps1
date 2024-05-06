# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Microsoft Azure Management is limited to administrative roles
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMAz1121($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz1121"
		FindingName	     = "CIS MAz 1.1.21 - Ensure Microsoft Azure Management is limited to administrative roles"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Blocking sign-in to Azure Management applications and portals enhances security of sensitive data by restricting access to privileged users. This mitigates potential exposure due to administrative errors or software vulnerabilities, as well as acting as a defense in depth measure against security breaches."
		Remediation	     = "Unfortunately we cannot accurately detect if correctly configured. If you have a existing policy. Please verify if the settings are configured correctly."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No Policy and Non-administrators can access the Azure AD administration portal"
		ExpectedValue    = "A Correctly Configured Policy Non-administrators cannot access the Azure AD administration portal"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Conditional Access: Cloud apps, actions, and authentication context'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-cloud-apps' })
	}
	return $inspectorobject
}

function Audit-CISMAz1121
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Select-Object * | Where-Object { $_.DisplayName -like "*administrative*" }
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
				}
				
			}
		}
		else
		{
			$Violation += "Could not verify is policy exists!"
		}
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISMAz1121($Violation)
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
return Audit-CISMAz1121