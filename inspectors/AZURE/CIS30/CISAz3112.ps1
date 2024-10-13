# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3112($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3112"
		FindingName	     = "CIS Az 3.1.1.2 - Microsoft Defender for Cloud Apps integration with Microsoft Defender for Cloud is not Selected"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Microsoft Defender for Cloud offers an additional layer of protection by using Azure Resource Manager events, which is considered to be the control plane for Azure. By analyzing the Azure Resource Manager records, Microsoft Defender for Cloud detects unusual or potentially harmful operations in the Azure subscription environment. Several of the preceding analytics are powered by Microsoft Defender for Cloud Apps. To benefit from these analytics, subscription must have a Cloud App Security license."
		Remediation	     = "Navigate to the PowerShellScript link, select the subscription and under Integration you select Allow Microsoft Defender for Cloud Apps to access my data"
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "On, if you have the license"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'What is Microsoft Defender for Cloud?'; 'URL' = 'https://learn.microsoft.com/en-in/azure/defender-for-cloud/defender-for-cloud-introduction#azure-management-layer-azure-resource-manager-preview' },
		@{ 'Name' = 'IM-9: Secure user access to existing applications'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-9-secure-user-access-to--existing-applications' })
	}
	return $inspectorobject
}

function Audit-CISAz3112
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq "MCAS"}
		
		# Validation
		if ($AzSecuritySetting.Enabled -eq $False)
		{
			$finalobject = Build-CISAz3112($AzSecuritySetting.Enabled)
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
return Audit-CISAz3112