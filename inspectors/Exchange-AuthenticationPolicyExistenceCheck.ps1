# This is an AuthenticationPolicyExistenceCheck Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the authentication Policy for Exchange is existing
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-AuthenticationPolicyExistenceCheck($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0008"
		FindingName	     = "Exchange does not have a Authentication Policy Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.1"
		Description	     = "Exchange Online faces a lot of attacks, attack vectors and malicious actors. Having BasicAuthenitcation not disabled leaves the M365 vulnerable for brute force attacks and weak security of accounts"
		Remediation	     = "Use the PowerShell script to set the Authentication Policy"
		PowerShellScript = 'Set-AuthenticationPolicy -Identity "<id>" -AllowBasicAuthActiveSync:$False -AllowBasicAuthAutodiscover:$False -AllowBasicAuthImap:$False -AllowBasicAuthMapi:$False -AllowBasicAuthOfflineAddressBook:$False -AllowBasicAuthOutlookService:$False -AllowBasicAuthPop:$False -AllowBasicAuthReportingWebServices:$False -AllowBasicAuthRest:$False -AllowBasicAuthRpc:$False -AllowBasicAuthSmtp:$False -AllowBasicAuthWebServices:$False -AllowBasicAuthPowershell:$FalsengWebServices $False -AllowBasicAuthRpc $False -AllowBasicAuthSmtp $False -AllowBasicAuthWebServices $False -AllowBasicAuthPowershell $False'
		DefaultValue	 = "No Authentication Policy"
		ExpectedValue    = "An Authentication Policy"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'PowerShell and Exchange Online Security'; 'URL' = 'https://www.scriptrunner.com/en/blog/powershell-and-exchange-online-security/' })
	}
	return $inspectorobject
}

function Audit-AuthenticationPolicyExistenceCheck
{
	try
	{
		$finalobject = @()
		$AuthenticationPolicy = Get-AuthenticationPolicy | Select *
		if ($AuthenticationPolicy -eq $null)
		{
			$endobject = Build-AuthenticationPolicyExistenceCheck("No Authentication Policy Found!")
			return $endobject
			
			return "No AuthenticationPolicy Found!"
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
				$endobject = Build-AuthenticationPolicyExistenceCheck($finalobject)
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
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}
return Audit-AuthenticationPolicyExistenceCheck