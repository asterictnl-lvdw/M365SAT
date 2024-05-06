# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On' (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2114($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2114"
		FindingName	     = "CIS Az 2.1.14 - Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "9.8"
		Description	     = "When Log Analytics agent for Azure VMs is turned on, Microsoft Defender for Cloud provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "By default, Automatic provisioning of monitoring agent is set to On."
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Microsoft Defender for Cloud data security'; 'URL' = 'https://docs.microsoft.com/en-us/azure/security-center/security-center-data-security' },
							@{ 'Name' = 'How does Defender for Cloud collect data?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components' })
	}
	return $inspectorobject
}

function Audit-CISAz2114
{
	try
	{
		$Setting = Get-AzSecurityAutoProvisioningSetting | Select-Object Name, AutoProvision
		
		
		if ($Setting.AutoProvision -match "Off")
		{
			$finalobject = Build-CISAz2114("AutoProvision: $($Setting.AutoProvision)")
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
return Audit-CISAz2114