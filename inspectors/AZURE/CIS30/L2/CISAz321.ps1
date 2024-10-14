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


function Build-CISAz321($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz321"
		FindingName	     = "CIS Az 3.2.1 - Ensure That Microsoft Defender for IoT Hub Is Set To 'On'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "IoT devices are very rarely patched and can be potential attack vectors for enterprise networks. Updating their network configuration to use a central security hub allows for detection of these breaches"
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#browse/Microsoft.Devices%2FIotHubs'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Microsoft Defender for IoT'; 'URL' = 'https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-iot#overview' },
							@{ 'Name' = 'Microsoft Defender for IoT KB'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-iot/' },
							@{ 'Name' = 'Microsoft Defender for IoT Pricing'; 'URL' = 'https://www.microsoft.com/en-us/security/business/endpoint-security/microsoft-defender-iot-pricing' },
							@{ 'Name' = 'Azure security baseline for Microsoft Defender for IoT'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/microsoft-defender-for-iot-security-baseline' },
							@{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' },
							@{ 'Name' = 'Quickstart: Enable Microsoft Defender for IoT on your Azure IoT Hub'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-iot/device-builders/quickstart-onboard-iot-hub' })
	}
	return $inspectorobject
}

function Audit-CISAz321
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/iotSecuritySolutions?api-version=2019-08-01").content | ConvertFrom-Json)
		
		if ([string]::IsNullOrEmpty($Settings.value))
		{
			$finalobject = Build-CISAz321("No Microsoft Defender for IoT Hub available!")
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
return Audit-CISAz321