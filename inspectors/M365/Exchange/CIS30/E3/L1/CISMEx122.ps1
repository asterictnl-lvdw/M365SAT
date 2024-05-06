# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure sign-in to shared mailboxes is blocked!
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx122($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx122"
		FindingName	     = "CIS MEx 1.2.2 - Sign-in to shared mailboxes is not blocked!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "7"
		Description	     = "The intent of the shared mailbox is the only allow delegated access from other mailboxes. An admin could reset the password or an attacker could potentially gain access to the shared mailbox allowing the direct sign-in to the shared mailbox and subsequently the sending of email from a sender that does not have a unique identity. To prevent this, block sign-in for the account that is associated with the shared mailbox."
		Remediation	     = "Use the PowerShell Script to disable sign-in into shared mailboxes."
		PowerShellScript = '$MBX = Get-EXOMailbox -RecipientTypeDetails SharedMailbox; $MBX | ForEach { Update-MgUser -UserId $_.ExternalDirectoryObjectId -AccountEnabled $false }'
		DefaultValue	 = "Null and 0 Mailboxes"
		ExpectedValue    = "False and 0 Mailboxes"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'About Shared Mailboxes'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/email/about-shared-mailboxes?view=o365-worldwide" },
			@{ 'Name' = 'Block Sign-In for the Shared Mailbox Account'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/email/create-a-shared-mailbox?view=o365-worldwide#block-sign-in-for-the-shared-mailbox-account" },
			@{ 'Name' = 'Block Microsoft 365 user accounts with PowerShell'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/block-user-accounts-with-microsoft-365-powershell?view=o365-worldwide#block-individual-user-accounts" })
	}
	return $inspectorobject
}

function Audit-CISMEx122
{
	try
	{
		# Actual Script
		$Count = 0
		$MBX = Get-Mailbox -RecipientTypeDetails SharedMailbox
		foreach ($Account in $MBX)
		{
			$AccountSetting = Get-MgUser -UserId $Account.ExternalDirectoryObjectId
			if ($AccountSetting.AccountEnabled -eq $false -or [string]::IsNullOrEmpty($AccountSetting.AccountEnabled))
			{
				
			}
			else
			{
				$Count++
			}
		}
		
		# Validation
		if ($Count -igt 0)
		{
			$MBX | ForEach { Get-MgUser -UserId $_.ExternalDirectoryObjectId } | Format-Table -AutoSize DisplayName, UserPrincipalName, AccountEnabled | Out-File "$path\CISMEx122-SharedMailboxesSignIn.txt"
			$finalobject = Build-CISMEx122($affectedmailboxes.Count)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx122