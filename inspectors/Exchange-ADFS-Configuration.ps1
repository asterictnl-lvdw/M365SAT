# This is an ADFSConfiguration Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if ADFS Configuration is correctly configured.
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-ADFSConfiguration($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0002"
		FindingName	     = "ADFS Configuration Found"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "Active Directory Federation Services (ADFS) configured on this Tenant. ADFS Claims Rules may act as replacements for some features in Azure, hence rendering certain findings a 'False Positive'"
		Remediation	     = "Review ADFS configuration for claims rules that may replace or negate findings in this report (eg, Forced MFA when outside of corporate networks)."
		PowerShellScript = ''
		DefaultValue	 = "None"
		ExpectedValue    = "Not applicable"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Active Directory Federation Services'; 'URL' = 'https://docs.microsoft.com/en-us/windows-server/identity/active-directory-federation-services' })
	}
	return $inspectorobject
}

function Inspect-ADFSConfiguration
{
	Try
	{
		
		$orgs_with_ADFS = @()
		Get-OrganizationConfig |
		ForEach-Object -Process { if ($null -ne $_.AdfsIssuer) { $orgs_with_ADFS += $_.Name; } }
		
		If ($orgs_with_ADFS.Count -NE 0)
		{
			
			$finalobject = Build-ADFSConfiguration($orgs_with_ADFS)
			return $finalobject
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
return Inspect-ADFSConfiguration


