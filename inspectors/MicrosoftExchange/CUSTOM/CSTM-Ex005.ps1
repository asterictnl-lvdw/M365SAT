# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if External Forwarding and AutoForwarding is correctly configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CSTM-Ex005($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex005"
		FindingName	     = "CSTM-Ex005 - External Forwarding and AutoForwarding is not correctly Configured"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.1"
		Description	     = "AllowedOOFType should not match 'External' and AutoForwardEnabled should not match 'True'. External Forwarding should be disabled to avoid information leaks and disclosure. Attackers often create these rules to exfiltrate data from your tenancy, this could be accomplished via access to an end-user account or otherwise."
		Remediation	     = 'Use the PowerShell Scripts: Get-TransportRule | Remove-TransportRule <br> Set-RemoteDomain Default -AutoForwardEnabled $false; $rejectMessageText = "{Your Reject Message}" and the PowerShell Script to create a TransportRule that blocks AutoForwarding'
		PowerShellScript = 'New-TransportRule -name "Client Rules To External Block" -Priority 0 -SentToScope NotInOrganization -FromScope InOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText'
		DefaultValue	 = "AllowedOOFType: External <br> AutoForwardEnabled: True"
		ExpectedValue    = "AllowedOOFType: Not External <br> AutoForwardEnabled: False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Procedures for mail flow rules in Exchange Server'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rule-procedures?view=exchserver-2019' },
			@{ 'Name' = 'Disable automatic forwarding in Office 365 and Exchange Server to prevent information leakage'; 'URL' = 'https://docs.microsoft.com/en-us/archive/blogs/exovoice/disable-automatic-forwarding-in-office-365-and-exchange-server-to-prevent-information-leakage' },
			@{ 'Name' = 'Set-RemoteDomain'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/exchange/set-remotedomain?view=exchange-ps' },
			@{ 'Name' = 'All you need to know about automatic email forwarding in Exchange Online'; 'URL' = 'https://techcommunity.microsoft.com/t5/exchange-team-blog/all-you-need-to-know-about-automatic-email-forwarding-in/ba-p/2074888#:~:text=%20%20%20Automatic%20forwarding%20option%20%20,%' })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex005
{
	try
	{
		$AutoForwardingExchangeData = @()
		$AutoForwardingExchange_1 = Get-RemoteDomain Default | select AllowedOOFType, AutoForwardEnabled
		$AutoForwardingExchange_2 = Get-TransportRule | Where-Object { $_.RedirectMessageTo -ne $null } | select Name, RedirectMessageTo
		$AutoForwardingExchange_3 = Get-TransportRule | where { $_.Identity -like '*Client Rules To External Block*' }
		
		if ($AutoForwardingExchange_1 -or $AutoForwardingExchange_2 -or $AutoForwardingExchange_3 -ne $null)
		{
			
			if ($AutoForwardingExchange_1.AllowedOOFType -match 'External' -and $AutoForwardingExchange_1.AutoForwardEnabled -match 'True')
			{
				$AutoForwardingExchangeData += " AllowedOOFType: " + $AutoForwardingExchange_1.AllowedOOFType
				$AutoForwardingExchangeData += "`n AutoForwardEnabled: " + $AutoForwardingExchange_1.AutoForwardEnabled
			}
			if (-not [string]::IsNullOrEmpty($AutoForwardingExchange_2))
			{
				
				foreach ($AutoForwardingExchangeDataObj2 in $AutoForwardingExchange_2)
				{
					
					$AutoForwardingExchangeData += " Name: " + $AutoForwardingExchange_2.Name
					$AutoForwardingExchangeData += "`n RedirectMessageTo: " + $AutoForwardingExchange_2.RedirectMessageTo
				}
			}
			if (-not [string]::IsNullOrEmpty($AutoForwardingExchange_3))
			{
				foreach ($AutoForwardingExchangeDataObj3 in $AutoForwardingExchange_3)
				{
					$AutoForwardingExchangeData += 'Identity: ' + $AutoForwardingExchange_3.Identity
				}
			}
		}
		if (-not [string]::IsNullOrEmpty($AutoForwardingExchangeData) -or $AutoForwardingExchangeData.Count -igt 0)
		{
			$finalobject = Build-CSTM-Ex005($AutoForwardingExchangeData)
			return $finalobject
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
return Audit-CSTM-Ex005