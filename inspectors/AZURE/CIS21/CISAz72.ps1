# Date: 25-1-2023071
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Virtual Machines are utilizing Managed Disks
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz72($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz72"
		FindingName	     = "CIS Az 7.2 - Virtual Machines are not utilizing Managed Disks"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Managed disks are by default encrypted on the underlying hardware, so no additional encryption is required for basic protection. It is available if additional encryption is required. Managed disks are by design more resilient that storage accounts. For ARM-deployed Virtual Machines, Azure Adviser will at some point recommend moving VHDs to managed disks both from a security and cost management perspective."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Stop-AzVM -ResourceGroupName $rgName -Name $vmName -Force; ConvertTo-AzVMManagedDisk -ResourceGroupName $rgName -VMName $vmName; Start-AzVM -ResourceGroupName $rgName -Name $vmName'
		DefaultValue	 = "Managed disks or are an option upon the creation of VMs"
		ExpectedValue    = "VMs with an Managed Disk."
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Frequently asked questions about Azure IaaS VM disks and managed and unmanaged premium disks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/faq-for-disks?tabs=azure-portal' })
	}
	return $inspectorobject
}

function Audit-CISAz72
{
	try
	{
		
		$Violation = @()
		$AzVMs = Get-AzVM | Select-Object Name, StorageProfile
		foreach ($AzVM in $AzVMs){
			if ($null -eq $AzVM.StorageProfile.OsDisk.ManagedDisk.Id){
				$Violation += $AzVM.Name
			}
		}

		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz72($Violation)
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
return Audit-CISAz72