# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Exchange
# Purpose: Ensure the Account Provisioning Activity report is reviewed at least weekly
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx231($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx231"
		FindingName	     = "CIS MEx 2.3.1 - Your Account Provisioning Activity report!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "0"
		Description	     = "f the organization doesn't usually use a third party provider to manage accounts, any entry on the list is likely illicit. However, if the organization uses a third party provider, it is recommended to monitor transaction volumes and look for new or unusual third party applications that may be managing users. If anything unusual is observed, the provider should be contacted to determine the legitimacy of the action."
		Remediation	     = "To verify the report is being reviewed at least weekly, confirm that the necessary procedures, by executing the PowerShell script and mapping it to a txt file."
		PowerShellScript = '$startDate = ((Get-date).AddDays(-7)).ToShortDateString(); $endDate = (Get-date).ToShortDateString(); Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate | Where-Object { $_.Operations -eq "add user." }'
		DefaultValue	 = "Undefined"
		ExpectedValue    = "Undefined"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Use DMARC to validate email'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email?view=o365-worldwide" },
			@{ 'Name' = 'DMARC Overview, Anatomy of a DMARC Record, How Senders Deploy DMARC in 5 Steps'; 'URL' = "https://dmarc.org/overview/" },
			@{ 'Name' = 'What is a DMARC record?'; 'URL' = "https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record" },
			@{ 'Name' = 'DMARC Configuration'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure?view=o365-worldwide" })
	}
}


function Inspect-CISMEx231
{	
	Try
	{
		[System.DateTime]$startDate = ((Get-date).AddDays(-7))
		[System.DateTime]$endDate = (Get-date)
		$AuditLog = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate | Where-Object { $_.Operations -eq "add user." } | Format-Table -AutoSize | Out-File "$path\CISMEx231-AccountProvisioningActivityReport.txt"
		$endobject = Build-CISMEx231($AuditLog)
		Return $endobject
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx231


