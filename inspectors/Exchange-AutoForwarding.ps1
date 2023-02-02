# This is an AutoForwardingExchange Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if AutoForwarding and External Forwarding is enabled 
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-AutoForwardingExchange($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID		      = "M365SATFMEX0009"
		FindingName   = "External Forwarding and AutoForwarding is not correctly Configured"
		ProductFamily = "Microsoft Exchange"
		CVS		      = "9.1"
		Description   = "AllowedOOFType should not match 'External' and AutoForwardEnabled should not match 'True'. External Forwarding should be disabled to avoid information leaks and disclosure. Attackers often create these rules to exfiltrate data from your tenancy, this could be accomplished via access to an end-user account or otherwise."
		Remediation   = "Use the PowerShell Scripts: Get-TransportRule | Remove-TransportRule <br> Set-RemoteDomain Default -AutoForwardEnabled $false; $rejectMessageText = '{Your Reject Message}' and the PowerShell Script to create a TransportRule that blocks AutoForwarding "
		PowerShellScript = 'New-TransportRule -name "Client Rules To External Block" -Priority 0 -SentToScope NotInOrganization -FromScope InOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText'
		DefaultValue  = "AllowedOOFType: External <br> AutoForwardEnabled: True"
		ExpectedValue = "AllowedOOFType: Not External <br> AutoForwardEnabled: False"
		ReturnedValue = $findings
		Impact	      = "Critical"
		RiskRating    = "Critical"
		References    = @(@{ 'Name' = 'Procedures for mail flow rules in Exchange Server'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rule-procedures?view=exchserver-2019' },
			@{ 'Name' = 'Disable automatic forwarding in Office 365 and Exchange Server to prevent information leakage'; 'URL' = 'https://docs.microsoft.com/en-us/archive/blogs/exovoice/disable-automatic-forwarding-in-office-365-and-exchange-server-to-prevent-information-leakage' },
			@{ 'Name' = 'Set-RemoteDomain'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/exchange/set-remotedomain?view=exchange-ps' },
			@{ 'Name' = 'All you need to know about automatic email forwarding in Exchange Online'; 'URL' = 'https://techcommunity.microsoft.com/t5/exchange-team-blog/all-you-need-to-know-about-automatic-email-forwarding-in/ba-p/2074888#:~:text=%20%20%20Automatic%20forwarding%20option%20%20,%' })
	}
	return $inspectorobject
}

function Audit-AutoForwardingExchange
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
				
				foreach ($AutoForwardingExchangeDataObj in $AutoForwardingExchange_1)
				{
					
					$AutoForwardingExchangeData += " AllowedOOFType: " + $AutoForwardingExchange_1.AllowedOOFType
					$AutoForwardingExchangeData += "`n AutoForwardEnabled: " + $AutoForwardingExchange_1.AutoForwardEnabled
				}
			}
			if (!$AutoForwardingExchange_2 -eq $null)
			{
				
				foreach ($AutoForwardingExchangeDataObj2 in $AutoForwardingExchange_2)
				{
					
					$AutoForwardingExchangeData += " Name: " + $AutoForwardingExchange_2.Name
					$AutoForwardingExchangeData += "`n RedirectMessageTo: " + $AutoForwardingExchange_2.RedirectMessageTo
				}
			}
			if ($AutoForwardingExchange_3 -eq $null)
			{
				$AutoForwardingExchangeData += 'Identity: ' + $AutoForwardingExchange_3.Identity
			}
		}
		if ($AutoForwardingExchangeData -ne $null)
		{
			$finalobject = Build-AutoForwardingExchange($AutoForwardingExchangeData)
			return $finalobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}
return Audit-AutoForwardingExchange