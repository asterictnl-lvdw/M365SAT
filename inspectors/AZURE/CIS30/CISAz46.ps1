# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Public Network Access' is `Disabled' for storage accounts (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz46($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz46"
		FindingName	     = "CIS Az 4.6 - 'Public Network Access' is Enabled for some storage accounts"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "The default network configuration for a storage account permits a user with appropriate permissions to configure public network access to containers and blobs in a storage account. Keep in mind that public access to a container is always turned off by default and must be explicitly configured to permit anonymous requests. It grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide public network access to storage accounts until, and unless, it is strongly desired. A shared access signature token or Azure AD RBAC should be used for providing controlled and timed access to blob containers."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -PublicNetworkAccess Disabled'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure anonymous read access for containers and blobs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal' },
		@{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
		@{ 'Name' = 'NS-2: Secure cloud native services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-2-secure-cloud-native-services-with-network-controls' },
		@{ 'Name' = 'Assign an Azure role for access to blob data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access?tabs=portal' },
		@{ 'Name' = 'Configure Azure Storage firewalls and virtual networks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz46
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName,ResourceGroupName,PublicNetworkAccess

		foreach ($StorageAccount in $StorageAccounts){
			if ($StorageAccount.PublicNetworkAccess -eq 'Enabled'){
				$violation += $context.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz46($violation)
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
return Audit-CISAz46