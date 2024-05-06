# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Enable Conditional Access policies to block legacy authentication
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5223($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5223"
		FindingName	     = "CIS MAz 5.2.2.3 - No Conditional Access policies to block legacy authentication"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "8.2"
		Description	     = "Legacy authentication protocols do not support multi-factor authentication. These protocols are often used by attackers because of this deficiency. Blocking legacy authentication makes it harder for attackers to gain access."
		Remediation	     = "Configure the policy at the ConditionalAccess Blade below in the PowerShell Script. There is a Policy Template available which you can create if there is no such policy created beforehand."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies '
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Policy"
		ReturnedValue    = "$findings"
		Impact		     = "5"
		Likelihood	     = "2"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Disable Basic authentication in Exchange Online'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/disable-basic-authentication-in-exchange-online' },
		@{ 'Name' = 'How to set up a multifunction device or application to send emails using Microsoft 365 or Office 365'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/how-to-set-up-a-multifunction-device-or-application-to-send-email-using-microsoft-365-or-office-365' },
		@{ 'Name' = 'Deprecation of Basic authentication in Exchange Online'; 'URL' = 'https://learn.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online' })
	}
	return $inspectorobject
}

function Audit-CISMAz5223
{
	try
	{
		# Actual Script
		$Violation = @()
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Select-Object * | Where-Object { $_.DisplayName -like "*Block legacy*" }
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5223-Get-BlockLegacyAuthConditionalAccessPolicy.txt"
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
					elseif ($PolicyInfo.conditions.applications.includeApplications -ne "All" -or $PolicyInfo.conditions.users.includeUsers -ne "All")
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
		# Verify if Exchange does not have Legacy Auth enabled
		$AuthPolicy = Get-AuthenticationPolicy | Format-Table Name -Auto
		$AuthPolicy | Format-Table -AutoSize | Out-File "$path\CISMAz5223-Get-BlockLegacyAuthConditionalAccessPolicy.txt" -Append
		if ($AuthPolicy -contains $null)
		{
			$Violation += "No Exchange Auth Policy Configured!"
		}
		else
		{
			$BasicAuthList = Get-AuthenticationPolicy | ForEach-Object { Get-AuthenticationPolicy $_.Name | Select-Object AllowBasicAuth* }
			foreach ($BasicAuthObj in $BasicAuthList)
			{
				if ($BasicAuthObj -ne $False)
				{
					$Violation += "$BasicAuthObj : False"
				}
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			
			$finalobject = Build-CISMAz5223($Violation)
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
return Audit-CISMAz5223