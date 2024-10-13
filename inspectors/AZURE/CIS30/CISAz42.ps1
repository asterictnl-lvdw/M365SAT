# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz42($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz42"
		FindingName	     = "CIS Az 3.2 - Setting ‘Enable Infrastructure Encryption’ for Some Storage Accounts in Azure Storage is not Set to ‘enabled’"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Azure Storage automatically encrypts all data in a storage account at the network level using 256-bit AES encryption, which is one of the strongest, FIPS 140-2-compliant block ciphers available. Customers who require higher levels of assurance that their data is secure can also enable 256-bit AES encryption at the Azure Storage infrastructure level for double encryption. Double encryption of Azure Storage data protects against a scenario where one of the encryption algorithms or keys may be compromised. Similarly, data is encrypted even before network transmission and in all backups. In this scenario, the additional layer of encryption continues to protect your data. For the most secure implementation of key based encryption, it is recommended to use a Customer Managed asymmetric RSA 2048 Key in Azure Key Vault."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <name> -AccountName <AccountName> -Location <Location> -SkuName "Standard_RAGRS" -Kind StorageV2 -RequireInfrastructureEncryption'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Check the encryption status of a blob'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/storage-blob-encryption-status?tabs=portal' },
							@{ 'Name' = 'Azure Storage encryption for data at rest'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-service-encryption' },
							@{ 'Name' = 'Enable infrastructure encryption for double encryption of data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable?tabs=portal' }
							@{ 'Name' = 'DP-4: Enable data at rest encryption by default'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default' })
	}
	return $inspectorobject
}

function Audit-CISAz42
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName,ResourceGroupName 
		foreach ($StorageAccount in $StorageAccounts){
			try{
				$StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Value[0] 
				$AzStorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountKey $StorageAccountKey -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
				$Containers = Get-AzStorageContainer -Context $AzStorageContext -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
				ForEach ($Container in $Containers){
					[Diagnostics.Trace]::Listeners.Clear()
					$Blobs = Get-AzStorageBlob -Container $Container.Name -Context $AzStorageContext -WarningAction SilentlyContinue
					ForEach ($Blob in $Blobs){
						$Check = $Blob | Select-Object -ExpandProperty ICloudBlob | Select-Object -ExpandProperty Properties | Select-Object IsServerEncrypted
						if ($Check.IsServerEncrypted -eq $False){
							$violation += $Blob.Name
						}
					}
					[Diagnostics.Trace]::Listeners.Clear()
				}
				
			}
			catch
			{
				continue
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz42($violation)
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
return Audit-CISAz42