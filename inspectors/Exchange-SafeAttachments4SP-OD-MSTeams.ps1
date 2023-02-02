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

function Build-SA4SPODMST($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0057"
		FindingName	     = "Safe Attachments is not Correctly Configured for SharePoint, OneDrive and Microsoft Teams"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Safe Attachments for SharePoint, OneDrive, and Microsoft Teams protects your organization from inadvertently sharing malicious files. If this is not enabled your organization might be at risk with malicious files are executed!"
		Remediation	     = "Use the PowerShell Scripts to enable ATP for SharePoint, OneDrive and MicrosoftTeams."
		PowerShellScript = 'Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true; Set-SPOTenant -DisallowInfectedFileDownload $true; New-ActivityAlert -Name "Malicious Files in Libraries" -Description "Notifies admins when malicious files are detected in SharePoint Online, OneDrive, or Microsoft Teams" -Category ThreatManagement -Operation FileMalwareDetected -NotifyUser "admin1@contoso.com","admin2@contoso.com"'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-for-spo-odfb-teams-configure?view=o365-worldwide" },
			@{ 'Name' = 'Set up Safe Attachments policies in Microsoft Defender for Office 365'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-attachments-policies-configure?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-SA4SPODMST
{
	try
	{
		$SA4SPODMST = Get-AtpPolicyForO365 | select Name, EnableATPForSPOTeamsODB
		if (-NOT $SA4SPODMST.EnableATPForSPOTeamsODB -match 'True')
		{
			$endobject = Build-SA4SPODMST('EnableATPForSPOTeamsODB: ' + $SA4SPODMST.EnableATPForSPOTeamsODB)
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
return Audit-SA4SPODMST
