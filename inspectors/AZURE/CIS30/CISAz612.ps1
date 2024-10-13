# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Diagnostic Setting captures appropriate categories
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz612($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz612"
		FindingName	     = "CIS Az 6.1.2 - Diagnostic Setting does not capture some appropriate categories"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzDiagnosticSetting'
		DefaultValue	 = "No Diagnostic Setting is set"
		ExpectedValue    = "Administrative,Alert,Policy,Security"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Diagnostic settings in Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings' },
		@{ 'Name' = 'Resource Manager template samples for diagnostic settings in Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-manager-diagnostic-settings?tabs=bicep' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' })
	}
	return $inspectorobject
}

function Audit-CISAz612
{
	try
	{
		$Violation = @()
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview").Content | ConvertFrom-Json).value.properties.logs
		foreach ($Setting in $Settings){
			if ($setting.category -eq 'Administrative' -or $setting.category -eq 'Alert' -or $setting.category -eq 'Policy' -or $setting.category -eq 'Security'){
				if ($Setting.enabled -eq $false)
				{

					$Violation += $setting.category
				}	
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
return Audit-CISAz612