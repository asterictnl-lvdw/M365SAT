# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure the spoofed domains report is reviewed weekly
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2111($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx2111"
		FindingName	     = "CIS MEx 2.1.11 - Your spoofed domains report!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "0"
		Description	     = "Bad actors spoof domains to trick users into conducting actions they normally would not or should not via phishing emails. Running this report will inform the message administrators of current activities, and the phishing techniques used by bad actors. This information can be used to inform end users and plan against future campaigns"
		Remediation	     = "To verify the report is being reviewed at least weekly, confirm that the necessary procedures, by executing the PowerShell script and mapping it to a txt file."
		PowerShellScript = 'Get-SpoofIntelligenceInsight'
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


function Inspect-CISMEx2111
{	
	Try
	{
			Get-SpoofIntelligenceInsight | Format-Table -AutoSize | Out-File "$path\CISMEx2111SpoofedDomainsReport.txt"
			$endobject = Build-CISMEx2111("0")
			Return $endobject
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx2111


