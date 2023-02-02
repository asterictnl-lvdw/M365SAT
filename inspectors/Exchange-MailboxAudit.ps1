# This is an MailboxAudit Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if MailboxAuditing is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-MailboxAudit($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID		      = "M365SATFMEX0040"
		FindingName   = "Mailbox auditing for all users is Disabled"
		ProductFamily = "Microsoft Exchange"
		CVS		      = "0.0"
		Description   = "By turning on mailbox auditing, Microsoft 365 back office teams can track logons to a mailbox as well as what actions are taken while the user is logged on."
		Remediation   = '$AuditAdmin = @("Copy", "Create", "FolderBind", "HardDelete", "MessageBind", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); $AuditDelegate = @("Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"); $AdminOwner = @("Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); Then use the PowerShell Script to remediate this issue.'
		PowerShellScript = "Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner"
		DefaultValue  = "False"
		ExpectedValue = "True"
		ReturnedValue = $findings
		Impact	      = "Informational"
		RiskRating    = "Informational"
		References    = @(@{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" },
			@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" })
	}
	return $inspectorobject
}

function Audit-MailboxAudit
{
	try
	{
		$MailboxAuditData = @()
		$MailboxAudit1 = Get-OrganizationConfig | select AuditDisabled
		$MailboxAudit2 = Get-mailbox | Where AuditEnabled
		if ($MailboxAudit1 -or $MailboxAudit2 -ne $null)
		{
			if ($MailboxAudit1.AuditDisabled -match 'True')
			{
				$MailboxAuditData += 'AuditDisabled: ' + $MailboxAudit1.AuditDisabled
			}
			if ($MailboxAudit2.AuditEnabled -match 'False')
			{
				$MailboxAuditData += '`n` AuditEnabled: ' + $MailboxAudit2.AuditEnabled
			}
			if ($MailboxAuditData -ne $null)
			{
				$endobject = Build-MailboxAudit($MailboxAuditData)
				return $endobject
			}
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
return Audit-MailboxAudit
