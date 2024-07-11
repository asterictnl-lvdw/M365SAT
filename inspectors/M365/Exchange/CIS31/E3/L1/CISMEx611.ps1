# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Exchange
# Purpose: Ensure 'AuditDisabled' organizationally is set to 'False' (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx611($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx611"
		FindingName	     = "CIS MEx 6.1.1 - Mailbox auditing is not Enabled for all users"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "Enforcing the default ensures auditing was not turned off intentionally or accidentally. Auditing mailbox actions will allow forensics and IR teams to trace various malicious activities that can generate TTPs caused by inbox access and tampering"
		Remediation	     = '$AuditAdmin = @("Copy", "Create", "FolderBind", "HardDelete", "MailItemsAccessed", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); $AuditDelegate = @("Create", "FolderBind", "HardDelete", "Move", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "SoftDelete", "Update", "UpdateFolderPermissions", "UpdateInboxRules"); $AdminOwner = @("Create", "HardDelete", "MailboxLogin", "Move", "MoveToDeletedItems", "SoftDelete", "Update", "UpdateCalendarDelegation", "UpdateFolderPermissions", "UpdateInboxRules"); Then use the PowerShell Script to remediate this issue.'
		PowerShellScript = 'Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 180 -AuditAdmin $AuditAdmin -AuditDelegate $AuditDelegate -AuditOwner $AuditOwner; Set-OrganizationConfig -AuditDisabled $false'
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

function Audit-CISMEx611
{
	try
	{
		$MailboxAudit1 = Get-OrganizationConfig | Select-Object AuditDisabled
		if ($MailboxAudit1 -ne $false)
		{
			$MailboxAudit1 | Format-Table -AutoSize | Out-File "$path\CISMEx611-MailboxAuditOrganizationConfig.txt"
			$endobject = Build-CISMEx611("AuditDisabled: $($MailboxAudit1)")
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
return Audit-CISMEx611
