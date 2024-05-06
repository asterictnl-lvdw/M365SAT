# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz116($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz116"
		FindingName	     = "CIS MAz 1.1.6 - Phishing-resistant MFA strength must be required for Administrators"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "8.2"
		Description	     = "Sophisticated attacks targeting MFA are more prevalent as the use of it becomes more widespread. These 3 methods are considered phishing-resistant as they remove passwords from the login workflow. It also ensures that public/private key exchange can only happen between the devices and a registered provider which prevents login to fake or phishing websites.."
		Remediation	     = "Configure the policy at the ConditionalAccess Blade below in the PowerShell Script. There is a Policy Template available which you can create if there is no such policy created beforehand."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No Policy"
		ExpectedValue    = ""
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Conditional Access authentication strength'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-strengths' })
	}
	return $inspectorobject
}

function Audit-CISMAz116
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Select-Object * | Where-Object { $_.DisplayName -like "*Phishing-resistant*" }
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
					if ($PolicyInfo.conditions.clientAppTypes -ne "all")
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.conditions.applications.includeApplications -ne "All")
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.grantControls.authenticationStrength.requirementsSatisfied -ne "mfa" -or $PolicyInfo.grantControls.authenticationStrength.allowedCombinations[0] -ne "windowsHelloForBusiness")
					{
						$Violation += $Policy.Id
					}
				}
				
			}
		}
		else
		{
			$Violation += "No Policy Configured!"
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISMAz116($Violation)
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
return Audit-CISMAz116