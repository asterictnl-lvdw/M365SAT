# This is an DoNotAllowInfectedFileSharePoint Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks if Infected Files can be downloaded through SharePoint
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-DoNotAllowInfectedFileSharePoint($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0003"
		FindingName	     = "Infected Files can be Downloaded through SharePoint"
		ProductFamily    = "Microsoft Sharepoint"
		CVS			     = "9.6"
		Description	     = "SharePoint online allows files that Defender for Office 365 has detected as infected to be downloaded. This could lead to serious damage to your organization"
		Remediation	     = "Use the PowerShell Script to mitigate this issue"
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOTenant -DisallowInfectedFileDownload $true'
		References	     = @(@{ 'Name' = 'Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/turn-on-mdo-for-spo-odb-and-teams?view=o365-worldwide' },
			@{ 'Name' = 'Built-in virus protection in SharePoint Online, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/virus-detection-in-spo?view=o365-worldwide' })
	}
}

function Audit-DoNotAllowInfectedFileSharePoint
{
	try
	{
		$DNAIFSP = Get-SPOTenant | Select-Object DisallowInfectedFileDownload
		if ($DNAIFSP.DisallowInfectedFileDownload -match 'False')
		{
			$endobject = Build-DoNotAllowInfectedFileSharePoint('DisallowInfectedFileDownload: ' + $DNAIFSP.DisallowInfectedFileDownload)
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
return Audit-DoNotAllowInfectedFileSharePoint