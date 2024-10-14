# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Unattached disks are encrypted with Customer Managed Key (CMK) (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz84($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz84"
		FindingName	     = "CIS Az 8.4 - Unattached disks are not encrypted with Customer Managed Keys (CMK)"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Encrypting the IaaS VM's OS disk (boot volume) and Data disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key, thus protecting the volume from unwanted reads. PMK (Platform Managed Keys) are enabled by default in Azure-managed disks and allow encryption at rest. CMK is recommended because it gives the customer the option to control which specific keys are used for the encryption and decryption of the disk. The customer can then change keys and increase security by disabling them instead of relying on the PMK key that remains unchanging. There is also the option to increase security further by using automatically rotating keys so that access to disk is ensured to be limited. Organizations should evaluate what their security requirements are, however, for the data stored on the disk. For high-risk data using CMK is a must, as it provides extra steps of security. If the data is low risk, PMK is enabled by default and provides sufficient data security."
		Remediation	     = "Use the below script to allow encryption on Azure VM Disks"
		PowerShellScript = 'Set-AzVMDiskEncryptionExtension -ResourceGroupName $VMRGname -VMName $vmName -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId;'
		DefaultValue	 = "By default, Unmanaged disks are encrypted using SSE with PMK."
		ExpectedValue    = "CMK Managed Disks"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Overview of managed disk encryption options'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption-overview' },
		@{ 'Name' = 'Use asset inventory to manage your resources security posture'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/asset-inventory?toc=%2Fazure%2Fsecurity%2Ftoc.json' },
		@{ 'Name' = 'DP-5: Use customer-managed key option in data at rest encryption when required'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required' })
	}
	return $inspectorobject
}

function Audit-CISAz84
{
	try
	{
		
		$Violation = @()
		$Disks = Get-AzDisk | Where-Object {$_.DiskState -eq 'Unattached'}
		foreach ($Disk in $Disks){
			if ($Disk.Encryption.Type -eq "EncryptionAtRestWithPlatformKey"){
				$Violation += $Disk.Name
			}
		}
			
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz84($Violation)
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
return Audit-CISAz84