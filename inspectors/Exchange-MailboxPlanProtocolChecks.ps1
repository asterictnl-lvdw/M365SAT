# This is an MailboxPlanProtocolChecks Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks Exchange Mailboxes with dangerous authentication protocols are enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-MailboxPlanProtocolChecks($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0048"
		FindingName	     = "MailboxPlans Have Legacy Protocols Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "8.2"
		Description	     = "For Exchange Online, Microsoft provides many protocols for end users to connect to their mailbox. We have IMAP, POP, ActiveSync, ECP, MAPI, OWA and more. Typically, we want to block less secure protocols like IMAP4 and POP3 so that users will not use these to connect a mailbox to."
		Remediation	     = "Execute the PowerShell command to disable the legacy protocols"
		PowerShellScript = 'New-AuthenticationPolicy -Name "Block Legacy Authentication"; Get-CASMailboxPlan -Filter {SmtpClientAuthenticationDisabled -eq "false" } | Set-CASMailboxPlan -ActiveSyncEnabled: $false -PopEnabled: $false -ImapEnabled: $false -MAPIEnabled: $false; Get-CASMailbox -Filter {SmtpClientAuthenticationDisabled -eq "true"} | Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} | Set-CASMailbox -ActiveSyncEnabled: $false -PopEnabled: $false -ImapEnabled: $false -MAPIEnabled: $false'
		DefaultValue	 = "ActiveSyncEnabled,PopEnabled,ImapEnabled,EwsEnabled,MapiEnabled = True"
		ExpectedValue    = "ActiveSyncEnabled,PopEnabled,ImapEnabled,EwsEnabled,MapiEnabled = False"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'How to: Block legacy authentication access to Azure AD with Conditional Access'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" },
			@{ 'Name' = 'How To Block Legacy Authentication Office 365'; 'URL' = "https://thesysadminchannel.com/use-conditional-access-to-block-legacy-authentication-in-office-365/" },
			@{ 'Name' = 'Block Legacy Authentication now, and do not wait for Microsoft'; 'URL' = "https://jeffreyappel.nl/block-legacy-authentication-now-and-dont-wait-for-microsoft/" })
	}
	return $inspectorobject
}

function Audit-MailboxPlanProtocolChecks
{
	try
	{
		#Mailbox Plans
		$finalobject = @()
		$MailboxPlans = @()
		$array = @("ActiveSyncEnabled", "PopEnabled", "ImapEnabled", "EwsEnabled", "MapiEnabled")
		$MailboxPlan = Get-CASMailboxPlan | select Name #Define the Names
		foreach ($Plan in $MailboxPlan)
		{
			$unit = Get-CASMailboxPlan $Plan.Name | Select Name, ActiveSyncEnabled, ImapEnabled, MAPIEnabled, PopEnabled, PopMessageDeleteEnabled, EwsEnabled
			$MailboxPlans += $unit
		}
		foreach ($plan in $MailboxPlans)
		{
			$finalobject += $Plan.Name
			foreach ($object in $Array)
			{
				if ($plan.$object -ne $false)
				{
					$object = "$($object): $($plan.$object)"
					$finalobject += $object
				}
			}
		}
		if ($finalobject.Count -ne 0)
		{
			$finalobject | Out-File -FilePath "$($OutPath)\logs\ExchangeMailboxesWithDangerousAuthProtocolsEnabled.txt" -Append
			$endobject = Build-MailboxPlanProtocolChecks($finalobject)
			Return $endobject
		}
		else
		{
			return null
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
return Audit-MailboxPlanProtocolChecks