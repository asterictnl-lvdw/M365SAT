# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz611($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz611"
		FindingName	     = "CIS Az 6.1.1 - 'Diagnostic Setting' does not exist for some Subscription Activity Logs"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzDiagnosticSetting'
		DefaultValue	 = "All False"
		ExpectedValue    = "All True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Azure Monitor data sources and data collection methods'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/data-sources#export-the-activity-log-with-a-log-profile' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' })
	}
	return $inspectorobject
}

function Audit-CISAz611
{
	try
	{
		#Subscription Based Checking
		$Violation = @()
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview").Content | ConvertFrom-Json).value.properties.logs
		foreach ($Setting in $Settings){
			if ($Setting.enabled -eq $false)
				{
					$Violation += $setting.category
				}
		}

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz611($Violation)
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
return Audit-CISAz611