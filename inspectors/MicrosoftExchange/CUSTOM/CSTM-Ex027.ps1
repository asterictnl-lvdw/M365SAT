# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: IP Addresses Spam checker
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex027($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex027"
		FindingName	     = "CSTM-Ex027 - MailboxPlans Have Legacy Protocols Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "8.2"
		Description	     = "For Exchange Online, Microsoft provides many protocols for end users to connect to their mailbox. We have IMAP, POP, ActiveSync, ECP, MAPI, OWA and more. Typically, we want to block less secure protocols like IMAP4 and POP3 so that users will not use these to connect a mailbox to."
		Remediation	     = "Execute the PowerShell command to disable the legacy protocols"
		PowerShellScript = 'New-AuthenticationPolicy -Name "Block Legacy Authentication"; Get-CASMailboxPlan -Filter {SmtpClientAuthenticationDisabled -eq "false" } | Set-CASMailboxPlan -ActiveSyncEnabled: $false -PopEnabled: $false -ImapEnabled: $false -MAPIEnabled: $false; Get-CASMailbox -Filter {SmtpClientAuthenticationDisabled -eq "true"} | Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} | Set-CASMailbox -ActiveSyncEnabled: $false -PopEnabled: $false -ImapEnabled: $false -MAPIEnabled: $false'
		DefaultValue	 = "ActiveSyncEnabled,PopEnabled,ImapEnabled,EwsEnabled,MapiEnabled = True"
		ExpectedValue    = "ActiveSyncEnabled,PopEnabled,ImapEnabled,EwsEnabled,MapiEnabled = False"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'How to: Block legacy authentication access to Azure AD with Conditional Access'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication" },
			@{ 'Name' = 'How To Block Legacy Authentication Office 365'; 'URL' = "https://thesysadminchannel.com/use-conditional-access-to-block-legacy-authentication-in-office-365/" },
			@{ 'Name' = 'Block Legacy Authentication now, and do not wait for Microsoft'; 'URL' = "https://jeffreyappel.nl/block-legacy-authentication-now-and-dont-wait-for-microsoft/" })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex027
{
	try
	{
		#Mailbox Plans
		$finalobject = @()
		$MailboxPlans = @()
		$array = @("ActiveSyncEnabled", "PopEnabled", "ImapEnabled", "EwsEnabled", "MapiEnabled")
		$MailboxPlan = Get-EXOCASMailbox | Select-Object Name, PrimarySmtpAddress #Define the Names
		foreach ($Plan in $MailboxPlan)
		{
			$unit = Get-CASMailbox -Identity $Plan.PrimarySmtpAddress | Select-Object Name, ActiveSyncEnabled, ImapEnabled, MAPIEnabled, PopEnabled, PopMessageDeleteEnabled, EwsEnabled
			$MailboxPlans += $unit
		}
		foreach ($plan in $MailboxPlans)
		{
			$finalobject += $Plan.Name
			foreach ($object in $array)
			{
				if ($plan.$object -ne $false)
				{
					$object = "$($object): $($plan.$object)"
					$finalobject += $object
				}
			}
		}
		if ($finalobject.Count -ne 0)
		{
			$finalobject | Out-File -FilePath "$path\ExchangeMailboxesWithDangerousAuthProtocolsEnabled.txt" -Append
			$endobject = Build-CSTM-Ex027($finalobject)
			Return $endobject
		}
		else
		{
			return null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Ex027