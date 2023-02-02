# This is an Audit-PublicGroups Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if public groups are existing withing Office 365 and Exchange
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-Audit-PublicGroups($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0055"
		FindingName	     = "Microsoft Exchange & Microsoft Office 365 Contains Public Groups"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "Ensure that only organizationally managed and approved public groups exist."
		Remediation	     = "In the Microsoft 365 Administration portal, go to: Teams&Groups > Select the Public Group > Go To Settings > Set Privacy To Private"
		PowerShellScript = '$publicgroups = Get-UnifiedGroup | ? { $_.AccessType -eq "Public"}'
		DefaultValue	 = "0"
		ExpectedValue    = "Approved Public Groups Documented"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Reference - Get-UnifiedGroup'; 'URL' = "https://learn.microsoft.com/en-us/powershell/module/exchange/get-unifiedgroup?view=exchange-ps" },
			@{ 'Name' = 'Group Self-Service'; 'URL' = "https://blogs.perficient.com/2016/03/07/office-365-have-you-evaluated-these-exchange-online-features/" })
	}
	return $inspectorobject
}

function Audit-PublicGroups
{
	try
	{
		Import-Module ExchangeOnlineManagement
		$publicgroupsdata = @()
		$publicgroups = Get-UnifiedGroup | ? { $_.AccessType -eq "Public" }
		if ($publicgroups -ne $null)
		{
			foreach ($publicgroupsdataobj in $publicgroups)
			{
				$publicgroupsdata += "$($publicgroups.DisplayName),$($publicgroups.AccessType)"
			}
			$endobject = Build-Audit-PublicGroups($publicgroupsdata)
			Return $endobject
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
return Audit-PublicGroups