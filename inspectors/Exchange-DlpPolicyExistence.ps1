# This is an DLPPolicyExistence Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the DLP Policy is existing
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-DLPPolicyExistence($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0020"
		FindingName	     = "DLP Policy is not configured!!"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "6.8"
		Description	     = "Enabling Data Loss Prevention (DLP) policies allows Exchange Online and SharePoint Online content to be scanned for specific types of data like social security numbers, credit card numbers, or passwords."
		Remediation	     = "Use the PowerShell script to configure a New-Dlp Compliance Policy"
		PowerShellScript = 'New-DlpPolicy -Name "Contoso PII"" -Template {templatehere}'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Policy"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'New-DlpPolicy'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/new-dlppolicy?view=exchange-ps" })
	}
	return $inspectorobject
}

function Audit-DLPPolicyExistence
{
	try
	{
		$dlppolicy = Get-DlpPolicy
		if ($dlppolicy -eq $null)
		{
			$endobject = Build-DLPPolicyExistence('No DLP Policy Existing!: ' + $dlppolicy)
			return $endobject
		}
		return $null
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
return Audit-DLPPolicyExistence