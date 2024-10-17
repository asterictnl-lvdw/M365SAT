# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz616($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz616"
		FindingName	     = "CIS Az 6.1.6 - Logging for Azure AppService 'HTTP logs' is NOT enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Capturing web requests can be important supporting information for security analysts performing monitoring and incident response activities. Once logging, these logs can be ingested into SIEM or other central aggregation point for the organization."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Set-AzStorageAccount'
		DefaultValue	 = "KeySource: Microsoft.Storage"
		ExpectedValue    = "KeySource: Microsoft.Keyvault"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Enable diagnostics logging for apps in Azure App Service'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' })
	}
	return $inspectorobject
}

function Audit-CISAz616
{
	try
	{
		$Violation = @()
		$WebApps = Get-AzWebApp -WarningAction SilentlyContinue -ProgressAction SilentlyContinue
		ForEach ($WebApp in $WebApps){
			if ($WebApp.Id.Contains('Microsoft.Web') -and $WebApp.Kind -ne 'functionapp'){
				$Settings = ((Invoke-AzRestMethod "https://management.azure.com/$($WebApp.Id)/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview").Content | ConvertFrom-Json).value.properties.logs
				if (-not [string]::IsNullOrEmpty($Settings)){
					foreach ($Setting in $Settings){
						if ($Setting.category -eq 'AppServiceHTTPLogs' -and $Setting.enabled -ne $true){
							$Violation += $WebApp.Name
						}
					}
				}
				else{
					$Violation += $WebApp.Name
				}
			}
		}
		
	

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz616($violation)
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
return Audit-CISAz616