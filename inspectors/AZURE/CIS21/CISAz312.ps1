# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Storage for Critical Data are Encrypted with Customer Managed Keys
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz312($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz312"
		FindingName	     = "CIS Az 3.12 - Some Storage for Critical Data is not Encrypted with Customer Managed Keys"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. If you want to control and manage this encryption key yourself, however, you can specify a customer-managed key. That key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault."
		Remediation	     = "You can change the settings in the by executing the written PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -Bypass AzureServices'
		DefaultValue	 = "Encryption: Microsoft Managed Keys"
		ExpectedValue    = "Encryption: Customer Managed Keys"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Azure Storage encryption for data at rest'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption' },
		@{ 'Name' = 'Protect data at rest'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices#protect-data-at-rest' },
		@{ 'Name' = 'About Azure Storage service-side encryption'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption#about-azure-storage-service-side-encryption' })			
	}
	return $inspectorobject
}

function Audit-CISAz312
{
	try
	{
		$violation = @()
		$contexts = Get-AzStorageAccount -ErrorAction SilentlyContinue
		
		foreach ($context in $contexts){
			$encryption = $context | Select-Object -ExpandProperty Encryption
			if ($encryption.KeySource -eq "Microsoft.Storage"){
				$violation += $context.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz312($violation)
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
return Audit-CISAz312