# This is an SMTPAuthGloballyDisabled Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if SMTP is globally disabled within Exchange
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-SMTPAuthGloballyDisabled($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0061"
		FindingName	     = "SMTP Authentication not Globally Disabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "SMTP Authentication is a method of authenticating to an Exchange Online mailbox to deliver email. Cyber adversaries have used SMTP authentication as a workaround for subtly conducting password spraying attacks or other credential-related attacks and bypassing multi-factor authentication protection because legacy authentication methods such as SMTP do not support MFA. There are two ways of disabling SMTP, globally and granularly on a per-user-mailbox level. It is recommended that SMTP Authentication be globally disabled if possible. Note that this may disrupt the functionality of legacy or other applications that require it or continued operations."
		Remediation	     = "Use the PowerShell to create a new SafeLinksPolicy to disable and enable all recommended settings!"
		PowerShellScript = 'Set-TransportConfig -SmtpClientAuthenticationDisabled $true'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Enable or disable authenticated client SMTP submission (SMTP AUTH) in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission" },
			@{ 'Name' = 'Set-CASMailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps" })
	}
	return $inspectorobject
}


function Inspect-SMTPAuthGloballyDisabled
{
	Try
	{
		
		# Query Security defaults to see if it's enabled. If it is, skip this check.
		$secureDefault = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -Property IsEnabled | Select-Object IsEnabled
		If ($secureDefault.IsEnabled -eq $false)
		{
			If (Get-TransportConfig | Where-Object { !$_.SmtpClientAuthenticationDisabled })
			{
				$endobject = Build-SMTPAuthGloballyDisabled("SmtpClientAuthenticationDisabled: $((Get-TransportConfig).SmtpClientAuthenticationDisabled)")
				Return $endobject
			}
		}
		
		return $null
		
	}
	Catch
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

return Inspect-SMTPAuthGloballyDisabled



