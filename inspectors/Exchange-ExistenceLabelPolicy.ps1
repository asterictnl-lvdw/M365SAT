# This is an ExistenceLabelPolicy Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the Label Policy is existing in the Exchange Tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-ExistenceLabelPolicy($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0022"
		FindingName	     = "No Label Policy Set! Data Classification not Available!"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "You should set up and use SharePoint Online data classification policies on data stored in your SharePoint Online sites."
		Remediation	     = "Use the PowerShell script to create a New Label Policy"
		PowerShellScript = 'New-LabelPolicy -Name "Example Name" -Labels "Example","Domain"'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Policy"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'New-LabelPolicy'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/new-labelpolicy?view=exchange-ps" })
	}
	return $inspectorobject
}

function Audit-ExistenceLabelPolicy
{
	try
	{
		Import-Module ExchangeOnlineManagement
		$ExistenceLabelPolicy = Get-LabelPolicy
		if ($ExistenceLabelPolicy -eq $null)
		{
			$endobject = Build-ExistenceLabelPolicy('No ExistenceLabelPolicy!')
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
return Audit-ExistenceLabelPolicy