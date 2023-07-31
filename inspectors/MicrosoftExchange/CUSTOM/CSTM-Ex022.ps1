# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Mailbox Auditing Tenant Level Check
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex022($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex022"
		FindingName	     = "CSTM-Ex022 - Mailbox Auditing Should is not enabled on tenant level"
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

function Inspect-CSTM-Ex022
{
	Try
	{
		
		$audit_disabled = (Get-OrganizationConfig).AuditDisabled
		
		If ($audit_disabled -eq $true)
		{
			$endobject = Build-CSTM-Ex022($audit_disabled)
			return $endobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex022


