# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Defender for Endpoint integration with Microsoft Defender for Cloud is selected
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz221($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz221"
		FindingName	     = "CIS Az 2.1.22 - Check if Microsoft Defender for IoT Hub Is Set To 'On'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "1"
		Description	     = "IoT devices are very rarely patched and can be potential attack vectors for enterprise networks. Updating their network configuration to use a central security hub allows for detection of these breaches."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Devices%2FIotHubs'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Microsoft Defender for IoT'; 'URL' = 'https://azure.microsoft.com/en-us/products/iot-defender/#overview' })
	}
	return $inspectorobject
}

function Audit-CISAz221
{
	try
	{
		$finalobject = Build-CISAz221("Unknown")
		return $finalobject
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz221