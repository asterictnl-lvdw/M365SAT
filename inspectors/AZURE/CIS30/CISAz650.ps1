# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz650($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz650"
		FindingName	     = "CIS Az 6.5.0 - SKU Basic/Consumption is used on artifacts that need to be monitored"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Typically, production workloads need to be monitored and should have an SLA with Microsoft, using Basic SKUs for any deployed product will mean that that these capabilities do not exist"
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzDiagnosticSetting'
		DefaultValue	 = "Application Insights are not enabled by default."
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Compare support plans'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview' },
		@{ 'Name' = 'Support scope and responsiveness'; 'URL' = 'https://azure.microsoft.com/en-us/support/plans/response/' })
	}
	return $inspectorobject
}

function Audit-CISAz650
{
	try
	{
		$Violation = @()
		$AzResources = Get-AzResource | Where-Object { $_.Sku -EQ "Basic"}
		Foreach ($AzResource in $AzResources){
				$Violation += $AzResource.Name
		}

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz650($violation)
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
return Audit-CISAz650