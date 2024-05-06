# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2115($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2115"
		FindingName	     = "CIS Az 2.1.15 - Auto provisioning of Log Analytics agent for Azure VMs is Set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "When Log Analytics agent for Azure VMs is turned on, Microsoft Defender for Cloud provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "On"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Azure custom roles'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles' },
			@{ 'Name' = 'Quickstart: Check access for a user to Azure resources'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access' })
	}
	return $inspectorobject
}

function Audit-CISAz2115
{
	try
	{
		$Setting = Get-AzSecurityAutoProvisioningSetting
		
		
		if ($Setting.AutoProvision -match "Off")
		{
			$finalobject = Build-CISAz2115($Setting.AutoProvision)
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
return Audit-CISAz2115