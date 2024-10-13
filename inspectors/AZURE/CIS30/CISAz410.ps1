# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Soft Delete is Enabled for Azure Containers and Blob Storage
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz410($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz410"
		FindingName	     = "CIS Az 4.10 - Soft Delete is not Enabled for some Azure Containers and Blob Storage"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Containers and Blob Storage data can be incorrectly deleted. An attacker/malicious user may do this deliberately in order to cause disruption. Deleting an Azure Storage blob causes immediate data loss. Enabling this configuration for Azure storage ensures that even if blobs/data were deleted from the storage account, Blobs/data objects are recoverable for a particular time which is set in the 'Retention policies,' ranging from 7 days to 365 days"
		Remediation	     = "You can change the settings in the by executing the written PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -Bypass AzureServices'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Soft delete for blobs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview' },
		@{ 'Name' = 'Soft delete for containers'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-overview' },
		@{ 'Name' = 'Enable and manage soft delete for containers'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-container-enable?tabs=azure-portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz410
{
	try
	{
		$violation = @()
		$contexts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName,ResourceGroupName
		foreach ($context in $contexts){
			$BlobServiceProperty = Get-AzStorageBlobServiceProperty -ResourceGroupName $context.ResourceGroupName -StorageAccountName $context.StorageAccountName
			foreach ($ServiceProperty in $BlobServiceProperty){
				$CDRP = $false
				$CDRPD = $false
				if ($ServiceProperty.ContainerDeleteRetentionPolicy.Enabled -eq $false){
					$CDRP = $true
				}elseif ($ServiceProperty.ContainerDeleteRetentionPolicy.Days -ilt 7 -or $ServiceProperty.ContainerDeleteRetentionPolicy.Days -igt 365){
					$CDRPD = $true
				}
				$DelRP =  $false
				$DelRPD = $false
				if ($ServiceProperty.DeleteRetentionPolicy.Enabled -eq $false){
					$DelRP =  $true
				}elseif ($ServiceProperty.DeleteRetentionPolicy.Days -ilt 7 -or $ServiceProperty.DeleteRetentionPolicy.Days -igt 365){
					$DelRPD = $true
				}
				if ($CDRP -eq $True -or $CDRPD -eq $True -or $DelRP -eq $True -or $DelRPD -eq $True){
					$violation += $ServiceProperty.StorageAccountName
				}
			}
		}
		
		
		# The script furthermore is unknown

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz410($violation)
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
return Audit-CISAz410