# This is an MSTeamsSettingsFileSharingOptions Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks the Microsoft Teams FileSharing Options
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSTeamsSettingsFileSharingOptions($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMST0010"
		FindingName	     = "Unapproved File Sharing Options are Enabled"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "6.5"
		Description	     = "Microsoft Teams enables collaboration via file sharing. This file sharing is conducted within Teams, using SharePoint Online, by default; however, third-party cloud services are allowed as well. "
		Remediation	     = "Use the PowerShell Script to disable the sharing options."
		DefaultValue	 = "All= True"
		ExpectedValue    = "All= False"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		PowerShellScript = 'Set-CsTeamsClientConfiguration -AllowGoogleDrive $false -AllowShareFile $false -AllowBox $false -AllowDropBox $false -AllowEgnyte $false'
		References	     = @(@{ 'Name' = 'Set up Skype for Business Online'; 'URL' = 'https://docs.microsoft.com/en-us/skypeforbusiness/set-up-skype-for-business-online/set-up-skype-for-business-online' })
	}
}


function Audit-MSTeamsSettingsFileSharingOptions
{
	try
	{
		$MSTeamsSettings_3Data = @()
		$MSTeamsSettings_3 = Get-CsTeamsClientConfiguration | select allow*
		if ($MSTeamsSettings_3.AllowDropBox -or $MSTeamsSettings_3.AllowGoogleDrive -or $MSTeamsSettings_3.AllowShareFile -or $MSTeamsSettings_3.AllowBox -or $MSTeamsSettings_3.AllowEgnyte -match 'True')
		{
			$MSTeamsSettings_3Data += " AllowDropBox: " + $MSTeamsSettings_3.AllowDropBox
			$MSTeamsSettings_3Data += "`n AllowGoogleDrive: " + $MSTeamsSettings_3.AllowGoogleDrive
			$MSTeamsSettings_3Data += "`n AllowShareFile: " + $MSTeamsSettings_3.AllowShareFile
			$MSTeamsSettings_3Data += "`n AllowBox: " + $MSTeamsSettings_3.AllowBox
			$MSTeamsSettings_3Data += "`n AllowEgnyte: " + $MSTeamsSettings_3.AllowEgnyte
			$endobject = Build-MSTeamsSettingsFileSharingOptions($MSTeamsSettings_3Data)
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
return Audit-MSTeamsSettingsFileSharingOptions