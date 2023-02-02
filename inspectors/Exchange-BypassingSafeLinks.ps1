# This is an BypassingSafeLinks Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if SafeLinks can be bypassed if they are marked unsafe by TransportRules
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-BypassingSafeLinks($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0014"
		FindingName	     = "The Safe Links Are not scanned and bypassed"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "In Exchange, it is possible to create mail transport rules that bypass the Safe Links detection capability. The rules listed above bypass the Safe Links capability. Consider reviewing these rules, as bypassing the Safe Links capability even for a subset of senders could be considered insecure depending on the context or may be an indicator of compromise."
		Remediation	     = "Use the Following PowerShell Script to mitigate this issue and remove the Transport Rules that bypass this issue."
		PowerShellScript = '$domains = Get-AcceptedDomain;New-SafeLinksPolicy -Name "Safe Links Policy" -IsEnabled $true -EnableSafeLinksForTeams $true -scanurls $true -DeliverMessageAfterScan $true -DoNotAllowClickThrough $true -AllowClickThrough $false -EnableForInternalSenders $true -DoNotTrackUserClicks $false -EnableSafeLinksForEmail $true -EnableSafeLinksForOffice $true; New-SafeLinksRule -Name "Safe Links Rule" -SafeLinksPolicy "Safe Links Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "No Transport Rule"
		ExpectedValue    = "No Transport Rule"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'How to Bypass Safe Link/Attachment Processing of Advanced Threat Protection (ATP)'; 'URL' = 'https://support.knowbe4.com/hc/en-us/articles/115004326408-How-to-Bypass-Safe-Link-Attachment-Processing-of-Advanced-Threat-Protection-ATP-' },
			@{ 'Name' = 'Undocumented Features: Safe Attachments, Safe Links, and Anti-Phishing Policies'; 'URL' = 'https://www.undocumented-features.com/2018/05/10/atp-safe-attachments-safe-links-and-anti-phishing-policies-or-all-the-policies-you-can-shake-a-stick-at/#Bypass_Safe_Attachments_Processing' })
	}
	return $inspectorobject
}

function Inspect-BypassingSafeLinks
{
	Try
	{
		
		$safe_links_bypass_rules = (Get-TransportRule | Where-Object { ($_.State -eq "Enabled") -and ($_.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeLinksProcessing") }).Identity
		
		If ($safe_links_bypass_rules.Count -ne 0)
		{
			$endobject = Build-BypassingSafeLinks($safe_attachment_bypass_rules)
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

return Inspect-BypassingSafeLinks


