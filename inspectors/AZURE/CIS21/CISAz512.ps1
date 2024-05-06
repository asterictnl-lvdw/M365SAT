# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Diagnostic Setting captures appropriate categories
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz512($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz512"
		FindingName	     = "CIS Az 5.1.2 - Diagnostic Setting does not capture some appropriate categories"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzDiagnosticSetting'
		DefaultValue	 = "No Categories Selected"
		ExpectedValue    = "Administrative,Alert,Policy,Security"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Diagnostic settings in Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings' },
		@{ 'Name' = 'Resource Manager template samples for diagnostic settings in Azure Monitor'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/resource-manager-diagnostic-settings?tabs=bicep' })
	}
	return $inspectorobject
}

function Audit-CISAz512
{
	try
	{
		$Violation = @()
		$DiagnosticSettings = Get-AzSubscriptionDiagnosticSetting 
		if (-not [string]::IsNullOrEmpty($DiagnosticSettings)){
			foreach ($DiagnosticSetting in $DiagnosticSettings){
				if ($DiagnosticSetting.Name -like "Administrative" -or $DiagnosticSetting.Name -like "Alert" -or $DiagnosticSetting.Name -like "Policy" -or $DiagnosticSetting.Name -like "Security"){
					if ($DiagnosticSetting.Log.Enabled -eq $False){
						$violation += $DiagnosticSetting.Name
					}
				}
			}
		}

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz512($violation)
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
return Audit-CISAz512