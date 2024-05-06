# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Application Insights are Configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz531($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz531"
		FindingName	     = "CIS Az 5.3.1 - Application Insights are not Configured"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Configuring Application Insights provides additional data not found elsewhere within Azure as part of a much larger logging and monitoring program within an organization's Information Security practice. The types and contents of these logs will act as both a potential cost saving measure (application performance) and a means to potentially confirm the source of a potential incident (trace logging). Metrics and Telemetry data provide organizations with a proactive approach to cost savings by monitoring an application's performance, while the trace logging data provides necessary details in a reactive incident response scenario by helping organizations identify the potential source of an incident within their application."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzApplicationInsights'
		DefaultValue	 = "Application Insights are not enabled by default."
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Application Insights overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/app/app-insights-overview' })
	}
	return $inspectorobject
}

function Audit-CISAz531
{
	try
	{
		$Violation = @()
		# It might happen that AzApplicationInsights returns null as then there is no misconfiguration
		$ApplicationInsights = Get-AzApplicationInsights
		foreach($ApplicationInsight in $ApplicationInsights){
			if ([string]::IsNullOrEmpty($ApplicationInsight)){
				$violation += "No ApplicationInsights Configured"
			}
		}


		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz531($violation)
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
return Audit-CISAz531