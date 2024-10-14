# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz640($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz640"
		FindingName	     = "CIS Az 6.4.0 - Azure Monitor Resource Logging is Disabled for some Services that Support it"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A lack of monitoring reduces the visibility into the data plane, and therefore an organization's ability to detect reconnaissance, authorization attempts or other malicious activity. Unlike Activity Logs, Resource Logs are not enabled by default. Specifically, without monitoring it would be impossible to tell which entities had accessed a data store that was breached. In addition, alerts for failed attempts to access APIs for Web Services or Databases are only possible when logging is enabled."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzDiagnosticSetting'
		DefaultValue	 = "Application Insights are not enabled by default."
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
		@{ 'Name' = 'LT-5: Centralize security log management and analysis'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis' },
		@{ 'Name' = 'Monitor Azure resources with Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/monitor-azure-resource' },
		@{ 'Name' = 'Supported Resource log categories for Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/reference/logs-index' },
		@{ 'Name' = 'Azure security logging and auditing'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/log-audit' },
		@{ 'Name' = 'Send Azure Monitor Activity log data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=powershell' },
		@{ 'Name' = 'Azure Key Vault logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/logging?tabs=Vault' },
		@{ 'Name' = 'Azure Monitor data sources and data collection methods'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/data-sources' },
		@{ 'Name' = 'Common and service-specific schemas for Azure resource logs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-logs-schema' },
		@{ 'Name' = 'Diagnostic logs - Azure Content Delivery Network'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cdn/cdn-azure-diagnostic-logs' })
	}
	return $inspectorobject
}

function Audit-CISAz640
{
	try
	{
		$Violation = @()
		$AzResources = Get-AzResource
		Foreach ($AzResource in $AzResources){
			$DiagnosticSetting = Get-AzDiagnosticSetting -ResourceId $AzResource.Id -ErrorAction SilentlyContinue
			if ([string]::IsNullOrEmpty($DiagnosticSetting)){
				$Violation += $AzResource.Name
			}
		}

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz640($violation)
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
return Audit-CISAz640