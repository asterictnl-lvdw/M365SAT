# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Private Endpoints are used to access Storage Accounts
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz310($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz310"
		FindingName	     = "CIS Az 3.10 - Private Endpoints are not used to access some Storage Accounts"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Securing traffic between services through encryption protects the data from easy interception and reading"
		Remediation	     = "You can change the settings in the by executing the written PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -Bypass AzureServices'
		DefaultValue	 = "By default, Private Endpoints are not created for Storage Accounts."
		ExpectedValue    = "A private endpoint used for access"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Use private endpoints for Azure Storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints' },
		@{ 'Name' = 'What is Azure Virtual Network?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview' },
		@{ 'Name' = 'Quickstart: Create a private endpoint by using the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-portal?tabs=dynamic-ip' },
		@{ 'Name' = 'Quickstart: Create a private endpoint by using the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/create-private-endpoint-cli?tabs=dynamic-ip' },
		@{ 'Name' = 'Tutorial: Connect to a storage account using an Azure Private Endpoint'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-storage-portal?tabs=dynamic-ip' })			
	}
	return $inspectorobject
}

function Audit-CISAz310
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount | Get-AzPrivateEndpoint

		if ([string]::IsNullOrEmpty($StorageAccounts)){
			return $null
		}
		
		# The script furthermore is unknown

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz310($violation)
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
return Audit-CISAz310