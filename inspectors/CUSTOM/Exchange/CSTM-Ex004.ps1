# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks the Authentication Policy Existence and if it is enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CSTM-Ex004($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex004"
		FindingName	     = "CSTM-Ex004 - Exchange does not have a Authentication Policy Enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "Exchange Online faces a lot of attacks, attack vectors and malicious actors. Having BasicAuthenitcation not disabled leaves the M365 vulnerable for brute force attacks and weak security of accounts"
		Remediation	     = "Use the PowerShell script to set the Authentication Policy"
		PowerShellScript = 'Set-AuthenticationPolicy -Identity "<id>" -AllowBasicAuthActiveSync:$False -AllowBasicAuthAutodiscover:$False -AllowBasicAuthImap:$False -AllowBasicAuthMapi:$False -AllowBasicAuthOfflineAddressBook:$False -AllowBasicAuthOutlookService:$False -AllowBasicAuthPop:$False -AllowBasicAuthReportingWebServices:$False -AllowBasicAuthRest:$False -AllowBasicAuthRpc:$False -AllowBasicAuthSmtp:$False -AllowBasicAuthWebServices:$False -AllowBasicAuthPowershell:$FalsengWebServices $False -AllowBasicAuthRpc $False -AllowBasicAuthSmtp $False -AllowBasicAuthWebServices $False -AllowBasicAuthPowershell $False'
		DefaultValue	 = "No Authentication Policy"
		ExpectedValue    = "An Authentication Policy"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'PowerShell and Exchange Online Security'; 'URL' = 'https://www.scriptrunner.com/en/blog/powershell-and-exchange-online-security/' })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex004
{
	try
	{
		$finalobject = @()
		$AuthenticationPolicy = Get-AuthenticationPolicy | Select-Object *
		if ([string]::IsNullOrEmpty($AuthenticationPolicy))
		{
			$endobject = Build-CSTM-Ex004("No Authentication Policy Found!")
			return $endobject
		}
		else
		{
			$array = @("AllowBasicAuth", "AllowBasicAuthActiveSync", "AllowBasicAuthImap", "AllowBasicAuthMapi", "AllowBasicAuthOfflineAddressBook", "AllowBasicAuthAutodiscover", "AllowBasicAuthOutlookService", "AllowBasicAuthPop", "AllowBasicAuthReportingWebService", "AllowBasicAuthRest", "AllowBasicAuthRpc", "AllowBasicAuthSmtp", "AllowBasicWebServices", "AllowBasicAuthPowershell")
			foreach ($policy in $AuthenticationPolicy)
			{
				$finalobject += $policy.Name
				foreach ($object in $array)
				{
					if ($policy.$object -eq $true)
					{
						$finalobject += $object
					}
				}
			}
			if ($finalobject.count -ne 0)
			{
				$endobject = Build-CSTM-Ex004($finalobject)
				return $endobject
			}
			else
			{
				return $null
			}
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Ex004