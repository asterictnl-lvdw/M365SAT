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


function Build-CISMAz113($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz113"
		FindingName	     = "CIS MAz 1.1.3 - Ensure Sign-in frequency is enabled and browser sessions are not persistent for Administrative users"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Forcing a time out for MFA will help ensure that sessions are not kept alive for an indefinite period of time, ensuring that browser sessions are not persistent will help in prevention of drive-by attacks in web browsers, this also prevents creation and saving of session cookies leaving nothing for an attacker to take."
		Remediation	     = "You can navigate to the Entry Portal and the Conditional Access blade to configure the policy."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "presistentBrowserMode: never and isEnabled: true | signInFrequencyValue: between 4 and 24 and timevalue: hours | clientAppTypes: All | applicationsIncludeApplications: All | grantControls.builtInControls: mfa"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure authentication session management with Conditional Access'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-session-lifetime' })
	}
	return $inspectorobject
}

function Audit-CISMAz113
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Select-Object * | Where-Object { $_.DisplayName -like "*Sign-In frequency*" }
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
					if (-not $PolicyInfo.SessionControls.persistentBrowser.mode -eq "never" -or $PolicyInfo.SessionControls.persistentBrowser.isEnabled -eq $False)
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.sessionControls.signInFrequency.value -lt 4 -and $PolicyInfo.sessionControls.signInFrequency.value -igt 24)
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.conditions.clientAppTypes -ne "all")
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.conditions.applications.includeApplications -ne "All")
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
			$Violation += "No Policy Configured!"
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISMAz113($Violation)
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
return Audit-CISMAz113