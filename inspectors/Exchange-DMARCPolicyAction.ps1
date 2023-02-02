# This is an DMARCPolicyAction Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks DMARC Policy Action exists
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-DMARCPolicyAction($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0071"
		FindingName	     = "Domains without DMARC Policy Action Configured"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "The domains listed above do not have a DMARC Policy Action configured. Domain-based Message Authentication, Reporting and Conformance (DMARC) is a security control that builds atop Sender Policy Framework and Domain-Keys Identified Mail to help control concerns related to the use of the organization's domain in malicious emails (email spoofing). The DMARC policy action is one of the most important components of DMARC and represents an action that the receiver of an email from the organization's domain should take if that email is identified as spoofed. If the current policy action is 'none' which means no action is taken against the malicious email and DMARC is in effect negated."
		Remediation	     = "If the organization's DMARC configuration is correct, consider changing the DMARC policy action to a more meaningful policy action such as 'quarantine' or 'reject'. This will direct mail recipient servers to not deliver messages which are identified as spoofed, therefore gaining a security benefit from DMARC. Note that this can cause interoperability issues and may result in undelivered emails in certain edge cases, with certain automated applications, or if the organization's DMARC settings are not correctly configured. It is recommended to have a mechanism by which users can report undelivered emails or other misbehaviors. Review the references on DMARC implementation below for more extensive advice to begin planning a DMARC rollout."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "Null"
		ExpectedValue    = "'p=quarantine' or 'p=reject'"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Use DMARC to validate email'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email?view=o365-worldwide" },
			@{ 'Name' = 'DMARC Overview, Anatomy of a DMARC Record, How Senders Deploy DMARC in 5 Steps'; 'URL' = "https://dmarc.org/overview/" },
			@{ 'Name' = 'What is a DMARC record?'; 'URL' = "https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record" })
	}
}


function Inspect-DMARCPolicyAction
{
	Try
	{
		
		$domains = Get-MgDomain | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
		$domains_without_actions = @()
		
		ForEach ($domain in $domains.Id)
		{
			($dmarc_record = ((nslookup -querytype=txt _dmarc.$domain 2>&1 | Select-String "DMARC1") -replace "`t", "")) | Out-Null
			
			If ($dmarc_record -Match "p=none;")
			{
				$domains_without_actions += "$domain policy: $(($dmarc_record -split ";")[1])"
			}
		}
		
		If ($domains_without_actions.Count -ne 0)
		{
			$endobject = Build-DMARCPolicyAction($domains_without_actions)
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

return Inspect-DMARCPolicyAction


