# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Exchange
# Purpose: Ensure 'AuditBypassEnabled' is not enabled on mailboxes
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx614($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx614"
		FindingName	     = "CIS MEx 6.1.4 - 'AuditBypassEnabled' is enabled on some mailboxes"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "If a mailbox audit bypass association is added for an account, the account can access any mailbox in the organization to which it has been assigned access permissions, without generating any mailbox audit logging entries for such access or recording any actions taken, such as message deletions. Enabling this parameter, whether intentionally or unintentionally, could allow insiders or malicious actors to conceal their activity on specific mailboxes. Ensuring proper logging of user actions and mailbox operations in the audit log will enable comprehensive incident response and forensics."
		Remediation	     = '$MBXAudit = Get-MailboxAuditBypassAssociation -ResultSize unlimited | Where-Object { $_.AuditBypassEnabled -eq $true }; foreach ($mailbox in $MBXAudit) { $mailboxName = $mailbox.Name; Set-MailboxAuditBypassAssociation -Identity $mailboxName -AuditBypassEnabled $false }'
		PowerShellScript = "Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner"
		DefaultValue	 = "0 (All False)"
		ExpectedValue    = "0 (All False)"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMEx614
{
	try
	{
		$MBX = Get-MailboxAuditBypassAssociation -ResultSize unlimited
		$AuditBypassCheck = $MBX | Where-Object { $_.AuditBypassEnabled -eq $true } | Format-Table Name, AuditBypassEnabled
		if ($AuditBypassCheck.Count -igt 0)
		{
			$MBX | Format-Table -AutoSize | Out-File "$path\CISMEx614-MailboxAuditBypassAssociation.txt"
			$endobject = Build-CISMEx614($AuditBypassCheck.Count)
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
return Audit-CISMEx614
