# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if SMTP Authentication is not Globally Disabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex032($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex032"
		FindingName	     = "CSTM-Ex032 - SMTP Authentication not Globally Disabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "SMTP Authentication is a method of authenticating to an Exchange Online mailbox to deliver email. Cyber adversaries have used SMTP authentication as a workaround for subtly conducting password spraying attacks or other credential-related attacks and bypassing multi-factor authentication protection because legacy authentication methods such as SMTP do not support MFA. There are two ways of disabling SMTP, globally and granularly on a per-user-mailbox level. It is recommended that SMTP Authentication be globally disabled if possible. Note that this may disrupt the functionality of legacy or other applications that require it or continued operations."
		Remediation	     = "Use the PowerShell to create a new SafeLinksPolicy to disable and enable all recommended settings!"
		PowerShellScript = 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Enable or disable authenticated client SMTP submission (SMTP AUTH) in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission" },
			@{ 'Name' = 'Set-CASMailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps" })
	}
	return $inspectorobject
}


function Inspect-CSTM-Ex032
{
	Try
	{
		
		# Query Security defaults to see if it's enabled. If it is, skip this check.
		$secureDefault = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -Property IsEnabled | Select-Object IsEnabled
		If ($secureDefault.IsEnabled -eq $false)
		{
			If (Get-TransportConfig | Where-Object { !$_.SmtpClientAuthenticationDisabled })
			{
				$endobject = Build-CSTM-Ex032("SmtpClientAuthenticationDisabled: $((Get-TransportConfig).SmtpClientAuthenticationDisabled)")
				Return $endobject
			}
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex032



