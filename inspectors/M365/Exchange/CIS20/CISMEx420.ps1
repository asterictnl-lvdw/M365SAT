# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Exchange Online Spam Policies are set to notify administrators
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx420($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx420"
		FindingName	     = "CIS MEx 4.2 - Exchange Online Spam Policies are not set to notify administrators"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "3"
		Description	     = "A blocked account is a good indication that the account in question has been breached and an attacker is using it to send spam emails to other people."
		Remediation	     = "Run the following PowerShell command"
		PowerShellScript = '$BccEmailAddress = @("<INSERT-EMAIL>"); $NotifyEmailAddress = @("<INSERT-EMAIL>"); Set-HostedOutboundSpamFilterPolicy -Identity Default BccSuspiciousOutboundAdditionalRecipients $BccEmailAddress -BccSuspiciousOutboundMail $true -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $NotifyEmailAddress'
		DefaultValue	 = "Not configured policy"
		ExpectedValue    = "A configured policy "
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Set-HostedOutboundSpamFilterPolicy Function Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-hostedoutboundspamfilterpolicy?view=exchange-ps" },
			@{ 'Name' = 'Configure Outbound Spam Notification Office 365 Exchange Online'; 'URL' = "http://www.thatlazyadmin.com/2019/04/01/configure-outbound-spam-notification-office-365-exchange-online/" })
	}
	return $inspectorobject
}


function Inspect-CISMEx420
{
	Try
	{
		$spamfilterviolation = @()
		$spamfilterpolicy = Get-HostedOutboundSpamFilterPolicy | Select-Object Bcc*, Notify*
		if ($spamfilterpolicy.BccSuspiciousOutboundMail -eq $false)
		{
			$spamfilterviolation += "BccSuspiciousOutboundMail: $($spamfilterpolicy.BccSuspiciousOutboundMail)"
		}
		if ($spamfilterpolicy.NotifyOutboundSpam -eq $false)
		{
			$spamfilterviolation += "NotifyOutboundSpam: $($spamfilterpolicy.NotifyOutboundSpam)"
		}
		If ($spamfilterviolation.count -igt 0)
		{
			$endobject = Build-CISMEx420($spamfilterviolation)
			Return $endobject
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx420


