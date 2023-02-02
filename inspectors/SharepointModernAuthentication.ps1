# This is an SharepointModernAuthentication Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks if SharePoint Modern Authentication is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SharepointModernAuthentication($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0008"
		FindingName	     = "SharePoint Online Modern Authentication is Not Enabled"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "9.3"
		Description	     = "Modern Authentication is a SharePoint Online setting that allows authentication features such as MFA, smart cards, and certificate-based authentication to function. These authentication features, particularly MFA, are vital for the secure operation of an organization. It is recommended to enable SharePoint modern authentication."
		Remediation	     = "Use the PowerShell Script to mitigate the issue."
		DefaultValue	 = "False"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOTenant -OfficeClientADALDisabled $false'
		References	     = @(@{ 'Name' = 'Reference - Set-SPOTenant'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' })
	}
}


function Inspect-SharepointModernAuthentication
{
	Try
	{
		
		$sharepoint_modern_auth_disabled = $(Get-SPOTenant).OfficeClientADALDisabled
		If ($sharepoint_modern_auth_disabled)
		{
			$setting = (Get-SPOTenant).OfficeClientADALDisabled
			$endobject = Build-SharepointModernAuthentication($setting)
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

return Inspect-SharepointModernAuthentication


