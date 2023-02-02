# This is an MailFlowRules Inspector.

# Date: 22-11-2022
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks for the Mail Transport Flow Rules if they exist
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Output for file
$path = @($OutPath)

function Build-MailFlowRules($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0032"
		FindingName	     = "Tenant Transport Rules"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "There are Transport Rules Existing in Microsoft Exchange, please verify if they are not faulty or have any malicious intend"
		Remediation	     = "Review Mail Flow rules and validate that all results are expected and no conflicting rules are in place."
		PowerShellScript = 'Remove-TransportRule -Identity ID'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.ToString()
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Manage Mail Flow Rules in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/manage-mail-flow-rules" })
	}
	return $inspectorobject
}

Function Inspect-MailFlowRules
{
	Try
	{
		$rules = Get-TransportRule
		
		If ($rules.count -gt 0)
		{
			$path = New-Item -ItemType Directory -Force -Path "$($path)\Mail-Flow-Rules"
			ForEach ($rule in $rules)
			{
				$name = $rule.Name
				
				$pattern = '[\\\[\]\{\}/():;\*]'
				
				$name = $name -replace $pattern, '-'
				
				$rule | Format-List | Out-File -FilePath "$($path)\$($name)_Mail-Flow-Rule.txt"
			}
			$endobject = Build-MailFlowRules($rules.Count)
			return $endobject
		}
		return $null
	}
	Catch
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

return Inspect-MailFlowRules


