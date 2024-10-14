# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Defender for Endpoint integration with Microsoft Defender for Cloud is selected
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3132($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3132"
		FindingName	     = "CIS Az 3.1.3.2 - Vulnerability Assessment for Machines component status is set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Microsoft Defender for Servers plan 2 licensing is required to remediate this issue. If you do not have this, please ignore this setting. Vulnerability assessment for machines scans for various security-related configurations and events such as system updates, OS vulnerabilities, and endpoint protection, then produces alerts on threat and vulnerability findings."
		Remediation	     = "Navigate to the PowerShellScript link, select the subscription and under Defender plans and Cloud Workload Protection, locate Server and check if the status is On"
		PowerShellScript = ''
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Plan your Defender for Servers deployment'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/plan-defender-for-servers' },
		@{ 'Name' = 'ES-1: Use Endpoint Detection and Response (EDR)'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr' })
	}
	return $inspectorobject
}

function Audit-CISAz3132
{
	try
	{
		#Get current Subscription ID
		$Subscription = (Get-AzContext).Subscription.Id
		# Since this requires Defender for Servers Plan 2 I cannot audit this, but this is the URL you can check to determine. All you need to do is modify the eq statement to the corresponding value.
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($Subscription)/providers/Microsoft.Security/pricings/CloudPosture?api-version=2023-01-01").Content | ConvertFrom-Json).properties.extensions | Where-Object {$_.name -eq ''}
		
		if ($Settings.isEnabled -eq 'False')
		{
			$finalobject = Build-CISAz3132("False")
			return $finalobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz3132