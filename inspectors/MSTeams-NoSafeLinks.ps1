# This is an NoSafeLinksForTeams Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks if SafeLinks is deactivated properly 
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-NoSafeLinksForTeams($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMST0008"
		FindingName   = "Safe Links for Teams is Not Enabled"
		ProductFamily = "Microsoft Teams"
		CVS		      = "9.6"
		Description   = "Safe Links is a feature of O365 that enables real-time detection of malicious links in incoming Exchange emails and other Office 365 applications. The Safe Links feature can also be enabled for links shared via Microsoft Teams. However, this setting is disabled in the 365 instance. Enabling it can decrease the risk of phishing and other attacks that might utilize malicious links sent via Teams, although it is not a panacea for these attacks."
		Remediation   = "Perhaps the most convenient way to enable this feature is to use the Set-SafeLinksPolicy command in PowerShell.. Note that some organizations may have chosen to disable Safe Links for Teams if it interferes with day-to-day operations, so key stakeholders should be surveyed before enabling Safe Links for Teams."
		DefaultValue  = "True"
		ExpectedValue = "True"
		ReturnedValue = $findings
		Impact	      = "Critical"
		RiskRating    = "Critical"
		PowerShellScript = '$domains = Get-AcceptedDomain;New-SafeLinksPolicy -Name "Safe Links Policy" -IsEnabled $true -EnableSafeLinksForTeams $true -scanurls $true -DeliverMessageAfterScan $true -DoNotAllowClickThrough $true -AllowClickThrough $false -EnableForInternalSenders $true -DoNotTrackUserClicks $false -EnableSafeLinksForEmail $true -EnableSafeLinksForOffice $true; New-SafeLinksRule -Name "Safe Links Rule" -SafeLinksPolicy "Safe Links Policy" -RecipientDomainIs $domains[0]'
		References	     = @(@{ 'Name' = 'Safe Links in Microsoft Defender for Office 365: Safe Links Settings for Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links?view=o365-worldwide#safe-links-settings-for-microsoft-teams' },
			@{ 'Name' = 'Set-SafeLinksPolicy Reference'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/exchange/set-safelinkspolicy?view=exchange-ps' },
			@{ 'Name' = 'Feature Roadmap for Safe Links for Microsoft Teams'; 'URL' = 'https://www.microsoft.com/en-us/microsoft-365/roadmap?rtc=2&filters=&searchterms=Safe%2CLinks%2CProtection%2Cfor%2CMicrosoft%2CTeams' })
	}
}

function Inspect-NoSafeLinksForTeams
{
	Try
	{
		
		Try
		{
			$safelinks_for_teams_policies = Get-SafeLinksPolicy | Where-Object { $_.EnableSafeLinksForTeams -ne $true }
			If (($safelinks_for_teams_policies | Measure-Object).Count -ne 0)
			{
				$endobject = Build-NoSafeLinksForTeams($safelinks_for_teams_policies.EnableSafeLinksForTeams)
				return $endobject
			}
		}
		Catch [System.Management.Automation.CommandNotFoundException] {
			return $null
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

return Inspect-NoSafeLinksForTeams


