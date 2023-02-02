# This is an BrowserIdleSignOutSharePoint Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks the Microsoft SharePoint Signs Out after Idling
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-BrowserIdleSignOutSharePoint($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0001"
		FindingName	     = "Sharepoint has no Idle Browser SignOut Configuration Configured"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "9.1"
		Description	     = "Idle session timeout in SharePoint Online is a security mechanism that warns and sign-outs the user after a period of inactivity. By default, idle session timeout settings are disabled in SharePoint Online. Not enabling leaves the user at risk for step-by attacks."
		Remediation	     = "Execute the following command to enable Idle Session Timeout= <b>  </b>"
		DefaultValue	 = 'Enabled= False, WarnAfter= 0, SignOutAfter= 0'
		ExpectedValue    = 'Enabled= True, WarnAfter= 30, SignOutAfter 60'
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOBrowserIdleSignOut -Enabled $true -WarnAfter (New-TimeSpan -Minutes 30) -SignOutAfter (New-TimeSpan -Minutes 60)'
		References	     = @(@{ 'Name' = 'Enforcing idle session timeout restrictions in SharePoint Online'; 'URL' = 'https://www.michev.info/Blog/Post/1857/enforcing-idle-session-timeout-restrictions-in-sharepoint-online' })
	}
}


function Audit-BrowserIdleSignOutSharePoint
{
	try
	{
		$command = Get-SPOBrowserIdleSignOut | select Enabled
		if ($command.Enabled -eq $false)
		{
			$endobject = Build-BrowserIdleSignOutSharePoint("SPOBrowserIdleSignOut: $($command.Enabled)")
			return $endobject
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
return Audit-BrowserIdleSignOutSharePoint