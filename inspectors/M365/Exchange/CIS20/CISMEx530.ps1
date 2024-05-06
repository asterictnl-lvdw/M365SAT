# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure mailbox auditing for all users is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx530($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx530"
		FindingName	     = "CIS MEx 5.3 - Mailbox auditing is not Enabled for all users"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "Starting in January 2019, Microsoft is turning on mailbox audit logging by default for all organizations. This means that certain actions performed by mailbox owners, delegates, and admins are automatically logged, and the corresponding mailbox audit records will be available when you search for them in the mailbox audit log. When mailbox auditing on by default is turned on for the organization, the AuditEnabled property for affected mailboxes won't be changed from False to True. In other words, mailbox auditing on by default ignores the AuditEnabled property on mailboxes. However, only certain mailbox types support default auditing On"
		Remediation	     = '$AuditAdmin = @("Copy", "Create", "FolderBind", "HardDelete", "MessageBind", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); $AuditDelegate = @("Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"); $AdminOwner = @("Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); Then use the PowerShell Script to remediate this issue.'
		PowerShellScript = "Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner"
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMEx530
{
	try
	{
		$MailboxAuditData = @()
		$MailboxAudit1 = Get-OrganizationConfig | select AuditDisabled
		$MailboxAudit2 = Get-mailbox | Where { $_.AuditEnabled -eq $false }
		if ($MailboxAudit1 -or $MailboxAudit2 -ne $null)
		{
			if ($MailboxAudit1.AuditDisabled -match 'True')
			{
				$MailboxAuditData += "AuditDisabled: $($MailboxAudit1.AuditDisabled)"
			}
			foreach ($Mailbox in $MailboxAudit2)
			{
				$MailboxAuditData += "AuditDisabled: $($Mailbox.Name)"
			}
			if ($MailboxAuditData.Count -igt 0)
			{
				$endobject = Build-CISMEx530($MailboxAuditData)
				return $endobject
			}
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx530
