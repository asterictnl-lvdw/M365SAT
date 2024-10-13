# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz48($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz48"
		FindingName	     = "CIS Az 4.8 - 'Allow Azure services on the trusted services list to access this storage account' is not Enabled for some Storage Account Access"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Turning on firewall rules for storage account will block access to incoming requests for data, including from other Azure services. We can re-enable this functionality by enabling 'Trusted Azure Services' through networking exception"
		Remediation	     = "You can change the settings in the by executing the written PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -Bypass AzureServices'
		DefaultValue	 = "Null"
		ExpectedValue    = "AzureServices"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure Azure Storage firewalls and virtual networks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal' },
		@{ 'Name' = 'NS-2: Secure cloud native services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls' })			
	}
	return $inspectorobject
}

function Audit-CISAz48
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount
		ForEach ($Account in $StorageAccounts){
			$NetworkSetting = $Account | Get-AzStorageAccountNetworkRuleSet | Select-Object Bypass
			if ($NetworkSetting.Bypass -ne 'AzureServices'){
				$violation += $context.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz48($violation)
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
return Audit-CISAz48