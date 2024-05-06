# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Exchange Online Spam Policies are set to notify administrators
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx216($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx216"
		FindingName	     = "CIS MEx 2.1.6 - Exchange Online Spam Policies are not set to notify administrators"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "3"
		Description	     = "A blocked account is a good indication that the account in question has been breached and an attacker is using it to send spam emails to other people."
		Remediation	     = "Run the following PowerShell command"
		PowerShellScript = '$BccEmailAddress = @("<INSERT-EMAIL>"); $NotifyEmailAddress = @("<INSERT-EMAIL>"); Set-HostedOutboundSpamFilterPolicy -Identity Default BccSuspiciousOutboundAdditionalRecipients $BccEmailAddress -BccSuspiciousOutboundMail $true -NotifyOutboundSpam $true -NotifyOutboundSpamRecipients $NotifyEmailAddress'
		DefaultValue	 = "BccSuspiciousOutboundMail: False / NotifyOutboundSpam: False"
		ExpectedValue    = "BccSuspiciousOutboundMail: True / NotifyOutboundSpam: True"
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


function Inspect-CISMEx216
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
			$spamfilterpolicy | Format-List | Out-File "$path\CISMEx216-AntiSpamPolicySettings.txt"
			$endobject = Build-CISMEx216($spamfilterviolation)
			Return $endobject
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx216


