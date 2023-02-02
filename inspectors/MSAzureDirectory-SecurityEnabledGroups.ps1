# This is an SecurityEnabledADGroups Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Security for Groups is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-SecurityEnabledADGroups($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0004"
		FindingName	     = "Multiple Groups Security Disabled"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "0.0"
		Description	     = "Multiple Groups in Azure Directory do not have any security restrictions enabled."
		Remediation	     = "Consider enabling Azure Directory Security for Groups to the respective groups"
		PowerShellScript = ''
		DefaultValue	 = "Not Enabled for Groups by Default"
		ExpectedValue    = "Enabled for Groups"
		ReturnedValue    = "Number of Groups without Security: $($findings)"
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Azure AD Groups - in a nutshell'; 'URL' = 'https://byteben.com/bb/azure-ad-groups-in-a-nutshell/' })
	}
}

function Audit-SecurityEnabledADGroups
{
	try
	{
		$object = @()
		$groups = Get-AzureADGroup -All $true | Where-Object { $_.SecurityEnabled -eq $False } | select DisplayName, SecurityEnabled
		$groupscount = $groups.SecurityEnabled.Count
		if ($groupscount -ne 0)
		{
			foreach ($group in $groups)
			{
				$object += "$($group.DisplayName): $($group.SecurityEnabled)"
			}
			$finalobject = Build-SecurityEnabledADGroups($groupscount)
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
return Audit-SecurityEnabledADGroups