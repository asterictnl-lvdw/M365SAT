# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure 'External sharing' of calendars is not available
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx230($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx230"
		FindingName	     = "CIS MEx 2.3 - External sharing of calendars is available!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "7"
		Description	     = "Attackers often spend time learning about organizations before launching an attack. Publicly available calendars can help attackers understand organizational relationships and determine when specific users may be more vulnerable to an attack, such as when they are traveling."
		Remediation	     = "Use the PowerShell Script to enable Modern Authentication for Microsoft Exchange Online. You can also check the text file which mailboxes have Calendar Sharing enabled."
		PowerShellScript = '$Policy = Get-SharingPolicy | Where-Object { $_.Domains -like " * CalendarSharing*" }; Set-SharingPolicy -Identity $Policy.Name -Enabled $False'
		DefaultValue	 = "True and Every Mailbox"
		ExpectedValue    = "False and 0 Mailboxes"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Share Microsoft 365 calendars with external users'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/manage/share-calendars-with-external-users?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMEx230
{
	try
	{
		# Actual Script
		$ExchangeSetting = Get-SharingPolicy | Where-Object { $_.Domains -like '*CalendarSharing*' }
		
		$affectedmailboxes = @()
		$mailboxes = Get-EXOMailbox -ResultSize Unlimited
		foreach ($mailbox in $mailboxes)
		{
			# Get the name of the default calendar folder (depends on the mailbox's language) 
			$calendarFolder = [string](Get-ExoMailboxFolderStatistics $mailbox.PrimarySmtpAddress -FolderScope Calendar | Where-Object { $_.FolderType -eq 'Calendar' }).Name
			# Get users calendar folder settings for their default Calendar folder # calendar has the format identity:\<calendar folder name> 
			$calendar = Get-MailboxCalendarFolder -Identity "$($mailbox.PrimarySmtpAddress):\$calendarFolder"
			if ($calendar.PublishEnabled)
			{
				Write-Warning "Calendar publishing is enabled for $($mailbox.PrimarySmtpAddress) on $($calendar.PublishedCalendarUrl)"
				$affectedmailboxes += "Calendar publishing is enabled for $($mailbox.PrimarySmtpAddress) on $($calendar.PublishedCalendarUrl)"
			}
		}
		
		# Validation
		if ($ExchangeSetting.Enabled -eq $true -or $affectedmailboxes.Count -igt 0)
		{
			$affectedmailboxes | Format-Table -AutoSize | Out-File "$path\CISMEx230CalendarSharingMailboxes.txt"
			$finalobject = Build-CISMEx230($affectedmailboxes.Count)
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
return Audit-CISMEx230