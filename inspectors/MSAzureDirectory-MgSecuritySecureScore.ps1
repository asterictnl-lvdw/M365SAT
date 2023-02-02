# This is an MgSecuritySecureScore Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks the security score of the Azure Tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-UsersWithNoMFAEnforced($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0019"
		FindingName	     = "Azure Security Score is not Maximum Value"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "0.0"
		Description	     = "Microsoft Azure encountered that your tenant has not maximum security enabled, thus your secure score could be improved. A lower secure score means that your tenant has recommendations based on security hardening to be able to be configured to enhance security."
		Remediation	     = "Please check the references URL for the actual score and what to fix."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "No Default Value"
		ExpectedValue    = "Maximum Score"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Security Microsoft - SecureScore'; 'URL' = "https://security.microsoft.com/securescore" })
	}
}

function Audit-MgSecuritySecureScore
{
	try
	{
		$command = Get-MgSecuritySecureScore -Top 1 | select CreatedDateTime, CurrentScore, MaxScore
		if ($command.CurrentScore -ne $command.MaxScore)
		{
			$endobject = Build-UsersWithNoMFAEnforced("MaxScore of $($command.CreatedDateTime) is not $($command.MaxScore), The CurrentScore is: " + $command.CurrentScore)
			Return $endobject
		}
		else
		{
			return $null
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
return Audit-MgSecuritySecureScore