# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Microsoft 365 audit log search is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx311($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx311"
		FindingName	     = "CIS MEx 3.1.1 - Microsoft 365 audit log search is Disabled!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "Enabling audit log search in the Microsoft Purview compliance portal can help organizations improve their security posture, meet regulatory compliance requirements, respond to security incidents, and gain valuable operational insights."
		Remediation	     = "Use the PowerShell script to enable the AuditLog in Microsoft Exchange"
		PowerShellScript = 'Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Enable/Disable the Audit Log'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/compliance/audit-log-enable-disable?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMEx311
{
	try
	{
		$AuditLog = Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
		
		if ($AuditLog.UnifiedAuditLogIngestionEnabled -ne $True)
		{
			$AuditLog | Format-Table -AutoSize | Out-File "$path\CISMEx311-UnifiedAuditLogIngestion.txt"
			$endobject = Build-CISMEx311($AuditLog.UnifiedAuditLogIngestionEnabled)
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
return Audit-CISMEx311