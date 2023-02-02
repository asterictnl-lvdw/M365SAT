# This is an BypassingSafeAttachments Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Attachments can be bypassed if they are marked unsafe by TransportRules
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-BypassingSafeAttachments($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0013"
		FindingName	     = "The Safe Attachments Are not scanned and bypassed"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "In Exchange, it is possible to create mail transport rules that bypass the Safe Attachments detection capability. The rules listed above bypass the Safe Attachments capability. Consider reviewing these rules, as bypassing the Safe Attachments capability even for a subset of senders could be considered insecure depending on the context or may be an indicator of compromise."
		Remediation	     = "Remove this transport rule so no Safe Attachments are bypassed and everything is monitored"
		PowerShellScript = '$domains = Get-AcceptedDomain;New-SafeAttachmentPolicy -Name "Safe Attachment Policy" -Enable $true -Redirect $false -RedirectAddress $ITSupportEmail New-SafeAttachmentRule -Name "Safe Attachment Rule" -SafeAttachmentPolicy "Safe Attachment Policy" -RecipientDomainIs $domains[0]'
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
# Define a function that we will later invoke.
# 365Inspect's built-in modules all follow this pattern.
function Inspect-BypassingSafeAttachments
{
	Try
	{
		
		# Query some element of the O365 environment to inspect. Note that we did not have to authenticate to Exchange
		# to fetch these transport rules within this module; assume main 365Inspect harness has logged us in already.
		$safe_attachment_bypass_rules = (Get-TransportRule | Where-Object { $_.SetHeaderName -eq "X-MS-Exchange-Organization-SkipSafeAttachmentProcessing" }).Identity
		
		# If some of the parsed O365 objects were found to have the security flaw this module is inspecting for,
		# return a list of those objects.
		If ($safe_attachment_bypass_rules.Count -ne 0)
		{
			$endobject = Build-BypassingSafeAttachments($safe_attachment_bypass_rules)
			return $endobject
		}
		
		# If none of the parsed O365 objects were found to have the security flaw this module is inspecting for,
		# returning $null indicates to 365Inspect that there were no findings for this module.
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

# Return the results of invoking the inspector function.
return Inspect-BypassingSafeAttachments


