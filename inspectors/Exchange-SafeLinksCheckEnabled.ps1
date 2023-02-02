# This is an SafeLinksCheckEnabled Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks the SafeLinks Policy more detailed on settings if they are enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-SafeLinksCheckEnabled($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0059"
		FindingName	     = "Microsoft Exchange Safe Links's one or more of the Safe Link Settings do not match the CIS Benchmark, thus Safe Links is not correctly configured"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Safe Links is a feature of O365 that enables real-time detection of malicious links in incoming Exchange emails and other Office 365 applications, such as Microsoft Teams. Safe Links is not enabled in the O365 tenant. This may be because the organization does not have the appropriate license level to use the feature, or because it has been disabled. This lowers the amount of built-in protection O365 offers the organization against phishing and other attacks."
		Remediation	     = "Safe Links can be configured by navigating to the Threat Management portal in the Office 365 Security and Compliance center. The first guide below is a quick introduction to enabling Safe Links while the second is a detailed reference."
		PowerShellScript = '$domains = Get-AcceptedDomain;New-SafeLinksPolicy -Name "Safe Links Policy" -IsEnabled $true -EnableSafeLinksForTeams $true -scanurls $true -DeliverMessageAfterScan $true -DoNotAllowClickThrough $true -AllowClickThrough $false -EnableForInternalSenders $true -DoNotTrackUserClicks $false -EnableSafeLinksForEmail $true -EnableSafeLinksForOffice $true; New-SafeLinksRule -Name "Safe Links Rule" -SafeLinksPolicy "Safe Links Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "IsEnabled: True <br /> AllowClickThrough: True <br /> DoNotAllowClickThrough: False <br /> ScanUrls: True <br /> EnableForInternalSenders: True <br /> EnableSafeLinksForTeams: True"
		ExpectedValue    = "IsEnabled: True <br /> AllowClickThrough: False <br /> DoNotAllowClickThrough: True <br /> ScanUrls: True <br /> EnableForInternalSenders: True <br /> EnableSafeLinksForTeams: True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Set up Safe Links policies in Microsoft Defender for Office 365'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-safe-links-policies?view=o365-worldwide" },
			@{ 'Name' = 'Microsoft Safe Links reference'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-SafeLinksCheckEnabled
{
	try
	{
		$auditsafelinkscheckdata = @()
		$auditsafelinkscheck = Get-SafeLinksPolicy | select IsEnabled, AllowClickThrough, DoNotAllowClickThrough, ScanUrls, EnableForInternalSenders, EnableSafeLinksForTeams
		if ($auditsafelinkscheck.IsEnabled -match 'False' -and $auditsafelinkscheck.AllowClickThrough -match 'True' -and $auditsafelinkscheck.DoNotAllowClickThrough -match 'False' -and $auditsafelinkscheck.ScanUrls -match 'False' -and $auditsafelinkscheck.EnableSafeLinksForTeams -match 'False')
		{
			$auditsafelinkscheckdata += " IsEnabled: " + $auditsafelinkscheck.IsEnabled
			$auditsafelinkscheckdata += "`n AllowClickThrough: " + $auditsafelinkscheck.AllowClickThrough
			$auditsafelinkscheckdata += "`n DoNotAllowClickThrough: " + $auditsafelinkscheck.DoNotAllowClickThrough
			$auditsafelinkscheckdata += "`n ScanUrls: " + $auditsafelinkscheck.ScanUrls
			$auditsafelinkscheckdata += "`n EnableSafeLinksForTeams: " + $auditsafelinkscheck.EnableSafeLinksForTeams
			$endobject = Build-SafeLinksCheckEnabled($auditsafelinkscheckdata)
			Return $endobject
		}
		Return $null
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
return Audit-SafeLinksCheckEnabled