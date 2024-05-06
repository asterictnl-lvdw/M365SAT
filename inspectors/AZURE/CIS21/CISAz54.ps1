# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz54($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz54"
		FindingName	     = "CIS Az 5.4 - Azure Monitor Resource Logging is not Enabled for All Services that Support it"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A lack of monitoring reduces the visibility into the data plane, and therefore an organization's ability to detect reconnaissance, authorization attempts or other malicious activity. Unlike Activity Logs, Resource Logs are not enabled by default. Specifically, without monitoring it would be impossible to tell which entities had accessed a data store that was breached. In addition, alerts for failed attempts to access APIs for Web Services or Databases are only possible when logging is enabled."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzApplicationInsights'
		DefaultValue	 = "Application Insights are not enabled by default."
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Monitor Azure resources with Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/monitor-azure-resource' },
		@{ 'Name' = 'Supported categories for Azure Monitor resource logs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/logs-index' },
		@{ 'Name' = 'Stream Azure Monitor activity log data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=powershell' },
		@{ 'Name' = 'Azure Key Vault logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/logging?tabs=Vault' },
		@{ 'Name' = 'Sources of monitoring data for Azure Monitor and their data collection methods'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/data-sources' },
		@{ 'Name' = 'Common and service-specific schemas for Azure resource logs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-logs-schema' },
		@{ 'Name' = 'Diagnostic logs - Azure Content Delivery Network'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cdn/cdn-azure-diagnostic-logs' })
	}
	return $inspectorobject
}

function Audit-CISAz54
{
	try
	{
		$Violation = @()
		# It might happen that AzApplicationInsights returns null as then there is no misconfiguration
		$Resources = Get-AzResource
		foreach ($Resource in $Resources){
			$diagnosticSetting = Get-AzDiagnosticSetting -ResourceId $resource.id -ErrorAction "SilentlyContinue";
			if ([string]::IsNullOrEmpty($diagnosticSetting)){
				$violation += "Diagnostic Settings not configured for resource: $($Resource.Name)"
			}
		}


		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz54($violation)
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
return Audit-CISAz54