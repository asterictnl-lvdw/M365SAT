# This is an TransportRulesallowlistIPs Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the Transport Rules have AllowList IPs
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-TransportRulesallowlistIPs($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0066"
		FindingName	     = "Email Security Checks are Bypassed Based on Sender IP"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "In the Exchange transport rules settings, it is possible to implement transport rules that bypass spam filtering and other email security capabilities (Exchange Online Protection) based on an IP address or domain (allowlisting). This makes a significant assumption of trust that should be reviewed and reconsidered. The transport rules listed herein bypass email security based on an IP address allowlist."
		Remediation	     = "Locate the rules M365SAT has identified (they are listed in this report) and determine who created the rules. Pursue a dialogue or analysis of whether the allowlisting is necessary for continued operations and whether another solution is possible. If the rules are not necessary, remove the rules."
		PowerShellScript = '$rejectMessageText = "YOURTEXTHERE";New-TransportRule -name "Client Rules To External Block" -Priority 0 -SentToScope NotInOrganization -FromScope InOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText Set-RemoteDomain -AutoForwardEnabled $false'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Manage Mail Flow Rules in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/manage-mail-flow-rules" },
			@{ 'Name' = 'Bypassing Exchange Online Protection in Office 365'; 'URL' = "https://docs.sophos.com/central/Customer/help/en-us/central/Customer/tasks/bypassingexchange.html" })
	}
	return $inspectorobject
}

function Inspect-TransportRulesallowlistIPs
{
	Try
	{
		
		$ip_allowlist_rules = (Get-TransportRule | Where { $_.SetSCL -AND ($_.SetSCL -as [int] -LE 0) -AND $_.SenderIPRanges }).Name
		
		If ($ip_allowlist_rules.Count -eq 0)
		{
			return $null
		}
		
		$endobject = Build-TransportRulesallowlistIPs($ip_allowlist_rules)
		Return $endobject
		
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

return Inspect-TransportRulesallowlistIPs


