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

function Build-CSTM-Ex029($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex029"
		FindingName	     = "CSTM-Ex029 - Outlook Web Application Offline Mode Enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "One of the oft-overlooked features of web mail, known as OWA, is the offline mode feature. This feature leaves an unencrypted copy of the last 500 emails on your device for easy access while you are not connected."
		Remediation	     = "Use the PowerShell Script to disable AllowOfflineOn for all computers"
		PowerShellScript = 'Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AllowOfflineOn NoComputers'
		DefaultValue	 = "No restrictions"
		ExpectedValue    = "NoComputers are allowed to AllowOfflineOn"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "4"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Disable offline access in Outlook on the Web at a global level'; 'URL' = "https://social.technet.microsoft.com/Forums/en-US/d2c2ff3f-232b-496b-a1dc-f2f402ae5c0a/disable-offline-access-in-outlook-on-the-web-at-a-global-level?forum=Exch2016Adm" },
			@{ 'Name' = 'Office 365 - Have You Evaluated These Exchange Online Features?'; 'URL' = "https://blogs.perficient.com/2016/03/07/office-365-have-you-evaluated-these-exchange-online-features/" })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex029
{
	$finalobject = @()
	try
	{
		#OWA Mailbox Policy Check Offline
		$OWAMailboxPolicies = Get-OwaMailboxPolicy | Select-Object Id, AllowOfflineOn
		foreach ($policy in $OWAMailboxPolicies)
		{
			$finalobject += $policy.Id
			if ($policy.AllowOfflineOn -eq "AllComputers")
			{
				$finalobject += "AllowOfflineOn: $($policy.AllowOfflineOn)"
			}
		}
		if ($finalobject.count -ne 0)
		{
			$endobject = Build-CSTM-Ex029($finalobject)
			Return $endobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Ex029