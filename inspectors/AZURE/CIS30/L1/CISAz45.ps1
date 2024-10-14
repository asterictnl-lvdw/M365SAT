# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose:  Ensure that Storage Account Access Keys are Periodically Regenerated
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz45($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz45"
		FindingName	     = "CIS Az 4.5 - Shared Access Signature Tokens Do not Expire Within an Hour"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A shared access signature (SAS) is a URI that grants restricted access rights to Azure Storage resources. A shared access signature can be provided to clients who should not be trusted with the storage account key but for whom it may be necessary to	delegate access to certain storage account resources. Providing a shared access signature URI to these clients allows them access to a resource for a specified period of time. This time should be set as low as possible and preferably no longer than an hour."
		Remediation	     = "There is no PowerShell script available. You must manually generate a SAS token and set the expiry"
		PowerShellScript = 'https://portal.azure.com/#browse/Microsoft.Storage%2FStorageAccounts'
		DefaultValue	 = "null"
		ExpectedValue    = "90"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Delegate access by using a shared access signature'; 'URL' = 'https://learn.microsoft.com/en-us/rest/api/storageservices/delegate-access-with-shared-access-signature' },
		@{ 'Name' = 'Grant limited access to Azure Storage resources using shared access signatures (SAS)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview' })
	}
	return $inspectorobject
}

function Audit-CISAz45
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName,ResourceGroupName 
		foreach ($StorageAccount in $StorageAccounts){
			try{
				$StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)[0].Value 
				$AzStorageContext = New-AzStorageContext -StorageAccountName $StorageAccount.StorageAccountName -StorageAccountKey $StorageAccountKey -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
				$AzKeyVaults = Get-AzKeyVault
				foreach ($Keyvault in $AzKeyVaults){
					$secrets = Get-AzKeyVaultSecret -VaultName $Keyvault.VaultName -ErrorAction SilentlyContinue
					foreach ($secret in $secrets){
						 # Retrieve the secret value as a SecureString
						$secretValue = $secret.SecretValue | ConvertFrom-SecureString -AsPlainText

						# Extract the expiry time from the secret value
						$expiryTimeString = ($secretValue -split '&') | Where-Object { $_ -like 'se=*' }

						# Extract the actual expiry time value from the string
						$expiryTimeValue = ($expiryTimeString -split '=')[1]

						# Decode the URL-encoded datetime string
						$decodedExpiryTimeValue = [System.Web.HttpUtility]::UrlDecode($expiryTimeValue)

						# Parse the decoded expiry time value as a datetime
						$expiryTime = [datetime]::Parse($decodedExpiryTimeValue)

						if ($expiryTime -igt (Get-Date).AddHours(1)) {
						} else {
							$violation += "Secret '$secretName' is still valid and set to expire at $expiryTime"
						}
					}
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
return Audit-CISAz45