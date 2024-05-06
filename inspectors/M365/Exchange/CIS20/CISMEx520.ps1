# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Microsoft 365 audit log search is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx520($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx520"
		FindingName	     = "CIS MEx 5.2 - Microsoft 365 audit log search is not Enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "Enabling audit log search in the Microsoft Purview compliance portal can help organizations improve their security posture, meet regulatory compliance requirements, respond to security incidents, and gain valuable operational insights."
		Remediation	     = "Use the PowerShell Script to Mitigate this issue."
		PowerShellScript = 'Enable-OrganizationCustomization; Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true; Set-AdminAuditLog -UnifiedAuditLogInvestigationEnabled $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "4"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Enabling the Unified Audit Log on all delegated Office 365 tenants via PowerShell'; 'URL' = 'https://gcits.com/knowledge-base/enabling-unified-audit-log-delegated-office-365-tenants-via-powershell/' },
		@{ 'Name' = 'Turn auditing on or off'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-enable-disable?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Audit-CISMEx520
{
	Try
	{
		$AdminAuditLogConfig = Get-AdminAuditLogConfig | FL UnifiedAuditLogIngestionEnabled
		
		
		
		If ($AdminAuditLogConfig.UnifiedAuditLogIngestionEnabled -eq $false)
		{
			$finding = $AdminAuditLogConfig.UnifiedAuditLogIngestionEnabled
			$finalobject = Build-CISMEx520($finding)
			return $finalobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Audit-CISMEx520


