# This is an AdditionalStorageProvidersAvailable Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Additional Storage Providers are enabled within the Tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-AdditionalStorageProvidersAvailable($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0001"
		FindingName	     = "Additional Storage Providers are Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.6"
		Description	     = "You should restrict storage providers that are integrated with Outlook on the Web. Not Restricting this could lead to information leakage and additional risk of infection from organizational non-trusted storage providers."
		Remediation	     = "Use the PowerShell Script to remediate this issue. You can check with the PowerShell command: <b>Get-OwaMailboxPolicy | Format-Table Name, AdditionalStorageProvidersAvailable</b> if the remediation has been successful!"
		PowerShellScript = 'Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -AdditionalStorageProvidersAvailable $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = "AdditionalStorageProvidersAvailable: " + $findings.AdditionalStorageProvidersAvailable
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Set-OwaMailboxPolicy'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/exchange/set-owamailboxpolicy?view=exchange-ps' })
	}
	return $inspectorobject
}

function Audit-AdditionalStorageProvidersAvailable
{
	try
	{
		$AdditionalStorageProvidersAvailable = Get-OwaMailboxPolicy | Select Name, AdditionalStorageProvidersAvailable
		if ($AdditionalStorageProvidersAvailable.AdditionalStorageProvidersAvailable -match 'True')
		{
			
			$finalobject = Build-AdditionalStorageProvidersAvailable($AdditionalStorageProvidersAvailable)
			return $finalobject
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
return Audit-AdditionalStorageProvidersAvailable