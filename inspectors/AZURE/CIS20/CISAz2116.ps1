# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Auto provisioning of 'Vulnerability assessment for machines' is Set to 'On'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2116($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2116"
		FindingName	     = "CIS Az 2.1.16 - Auto provisioning of Vulnerability assessment for machines is Set to Off"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Vulnerability assessment for machines scans for various security-related configurations and events such as system updates, OS vulnerabilities, and endpoint protection, then produces alerts on threat and vulnerability findings."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "Null"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'How does Defender for Cloud collect data?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components?tabs=autoprovision-va' })
	}
	return $inspectorobject
}

function Audit-CISAz2116
{
	try
	{
		$SubScriptionID = Get-AzSubscription
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubScriptionID.id)/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings?api-version=2022-01-01-preview").content | ConvertFrom-Json | Select-Object properties)
		
		if ([string]::IsNullOrEmpty($Settings))
		{
			$finalobject = Build-CISAz2116("Null")
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
return Audit-CISAz2116