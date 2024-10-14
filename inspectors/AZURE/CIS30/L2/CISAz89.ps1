# Date: 25-1-2023071
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Only Approved Extensions Are Installed
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz89($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz89"
		FindingName	     = "CIS Az 8.9 - Some VHDs / OS / Data Disks are not Encrypted"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "While it is recommended to use Managed Disks which are encrypted by default, 'legacy' VHDs may exist for a variety of reasons and may need to remain in VHD format. VHDs are not encrypted by default, so this recommendation intends to address the security of these disks. In these niche cases, VHDs should be encrypted using the procedures in this recommendation to encrypt and protect the data content."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'New-AzKeyvault -name <name> -ResourceGroupName <resourceGroup> -Location <location> -EnabledForDiskEncryption; $KeyVault = Get-AzKeyVault -VaultName <name> -ResourceGroupName <resourceGroup>; Set-AzVMDiskEncryptionExtension -ResourceGroupName <resourceGroup> -VMName <name> -DiskEncryptionKeyVaultUrl $KeyVault.VaultUri -DiskEncryptionKeyVaultId $KeyVault.ResourceId'
		DefaultValue	 = "NO Encryption"
		ExpectedValue    = "Encryption"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Quickstart: Create and encrypt a Windows VM with the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-cli-quickstart' },
		@{ 'Name' = 'Quickstart: Create and encrypt a Windows virtual machine in Azure with PowerShell'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-powershell-quickstart' },
		@{ 'Name' = 'DP-4: Enable data at rest encryption by default'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default' },
		@{ 'Name' = 'Create a managed disk from a VHD file in a storage account in same or different subscription with PowerShell'; 'URL' = 'https://learn.microsoft.com/en-us/previous-versions/azure/virtual-machines/scripts/virtual-machines-powershell-sample-create-managed-disk-from-vhd' })
	}
	return $inspectorobject
}

function Audit-CISAz89
{
	try
	{
		
		$Violation = @()

		$AzVMs = Get-AzVM | Select-Object ResourceGroupName,Name -ExpandProperty StorageProfile
		if ($null -ne $AzVMs.OsDisk.Vhd){
			#Check for encryption status for VHD
			foreach ($AzVM in $AzVMs){
				$Encryption = Get-AzVmDiskEncryptionStatus -ResourceGroupName $AzVM.ResourceGroupName -VMName $AzVM.Name
				if ($Encryption.DataVolumesEncrypted -eq "NotEncrypted" -or $Encryption.OsVolumeEncrypted -eq "NotEncrypted"){
					$Violation += $AzVM.Name
				}
			}
		}else{
			#Check for regular encryption
			foreach ($AzVM in $AzVMs){
				$Encryption = Get-AzVmDiskEncryptionStatus -ResourceGroupName $AzVM.ResourceGroupName -VMName $AzVM.Name
				if ($Encryption.DataVolumesEncrypted -eq "NotEncrypted" -or $Encryption.OsVolumeEncrypted -eq "NotEncrypted"){
					$Violation += $AzVM.Name
				}
			}
		}


		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz89($Violation)
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
return Audit-CISAz89