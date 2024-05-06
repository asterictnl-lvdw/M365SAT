# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz516($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz516"
		FindingName	     = "CIS Az 5.1.6 - Logging for Azure AppService 'HTTP logs' is NOT enabled"
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
		References	     = @(@{ 'Name' = 'Enable diagnostics logging for apps in Azure App Service'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs' })
	}
	return $inspectorobject
}

function Audit-CISAz516
{
	try
	{
		$Violation = @()
		# There is no script available at this moment to verify this clause
	

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz516($violation)
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
return Audit-CISAz516