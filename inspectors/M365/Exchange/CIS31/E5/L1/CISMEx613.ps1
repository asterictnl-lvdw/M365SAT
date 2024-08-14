# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Exchange
# Purpose: Ensure mailbox auditing for E5 users is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx613($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx613"
		FindingName	     = "CIS MEx 6.1.3 - Mailbox auditing for E5 users is not enabled!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "Whether it is for regulatory compliance or for tracking unauthorized configuration changes in Microsoft 365, enabling mailbox auditing, and ensuring the proper mailbox actions are accounted for allows for Microsoft 365 teams to run security operations, forensics or general investigations on mailbox activities"
		Remediation	     = '$AuditAdmin = @("Copy", "Create", "FolderBind", "HardDelete", "MessageBind", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); $AuditDelegate = @("Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"); $AdminOwner = @("Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); Then use the PowerShell Script to remediate this issue.'
		PowerShellScript = '$MBX = Get-EXOMailbox -ResultSize Unlimited | Where-Object {$_.RecipientTypeDetails -eq "UserMailbox" }; $MBX | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner'
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

function VerifyActions { 
	param ( [string]$type, [array]$actions, [array]$auditProperty, [string]$mailboxName) 
	$missingActions = @() 
	$actionCount = 0 
	foreach ($action in $actions) 
	{ 
		if ($auditProperty -notcontains $action) 
		{ 
			$missingActions += "[$mailboxName] Failure: Audit action '$action' missing from $type" 
			$actionCount++ 
		} 
	} if ($actionCount -eq 0) 
	{ 
		return $null
	} 
	else 
	{ 
		return $missingActions
	} 
}

function Audit-CISMEx613
{
	try
	{
		$AdminActions = @( "ApplyRecord", "Copy", "Create", "FolderBind", "HardDelete", "MailItemsAccessed", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "Send", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules" ) 
		$DelegateActions = @( "ApplyRecord", "Create", "FolderBind", "HardDelete", "Move", "MailItemsAccessed", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules" ) 
		$OwnerActions = @( "ApplyRecord", "Create", "HardDelete", "MailboxLogin", "Move", "MailItemsAccessed", "MoveToDeletedItems", "Send", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules" )
		$violation = @()
		$missingActions = @()
		#$mailboxes = Get-EXOMailbox -PropertySets Audit,Minimum -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" } 
		$mailboxes = Get-Mailbox -ResultSize Unlimited | Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" } 
	foreach ($mailbox in $mailboxes) 
	{ 
		if ($mailbox.AuditEnabled) 
		{ 
		} 
		else 
		{ 
			$violation += $mailbox.UserPrincipalName 
		} 
		$missingActions += VerifyActions -type "AuditAdmin" -actions $AdminActions -auditProperty $mailbox.AuditAdmin -mailboxName $mailbox.UserPrincipalName 
		$missingActions += VerifyActions -type "AuditDelegate" -actions $DelegateActions -auditProperty $mailbox.AuditDelegate -mailboxName $mailbox.UserPrincipalName 
		$missingActions += VerifyActions -type "AuditOwner" -actions $OwnerActions -auditProperty $mailbox.AuditOwner -mailboxName $mailbox.UserPrincipalName 
	}
		if ($violation.Count -igt 0 -or $missingActions.Count -igt 0)
		{
			$violation | Format-Table -AutoSize | Out-File "$path\CISMEx613-MailboxAuditSettingsPerE5User.txt"
			$missingActions | Format-Table -AutoSize | Out-File "$path\CISMEx613-MailboxAuditSettingsPerE5User.txt" -Append
			$endobject = Build-CISMEx613("file://$path/CISMEx613-MailboxAuditSettingsPerE5User.txt")
			return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx613




