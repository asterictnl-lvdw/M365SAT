# This is an MailboxAuditingAtTenantLevel Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if MailboxAuditing is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-MailboxAuditingAtTenantLevel($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0041"
		FindingName	     = "Mailbox Auditing Should is not enabled on tenant level"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "3.0"
		Description	     = "Mailbox Auditing is an Exchange mailbox feature that, when activated, generates audit logs for events related to a user's use of email. This is one of the most oft-recommended security improvements to Exchange because mailbox audit logs can contain information critical in a detection or response scenario such as triaging a business email compromise. Mailbox auditing can be globally enabled at the tenant level, which supersedes all per-mailbox settings, but it is not currently enabled."
		Remediation	     = "Mailbox auditing can be globally enabled within the Tenant using the Set-OrganizationConfig commandlet."
		PowerShellScript = 'Set-OrganizationConfig -AuditDisabled $false'
		DefaultValue	 = "False"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		References	     = @(@{ 'Name' = 'Manage mailbox auditing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/enable-mailbox-auditing?view=o365-worldwide" },
			@{ 'Name' = 'Set-OrganizationConfig Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-organizationconfig?view=exchange-ps" })
	}
	return $inspectorobject
}

function Inspect-MailboxAuditingAtTenantLevel
{
	Try
	{
		
		$audit_disabled = (Get-OrganizationConfig).AuditDisabled
		
		If ($audit_disabled -eq $true)
		{
			$endobject = Build-MailboxAuditingAtTenantLevel($audit_disabled)
			return $endobject
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

return Inspect-MailboxAuditingAtTenantLevel


