# Date: 25-1-2023071
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Only Approved Extensions Are Installed
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz75($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz75"
		FindingName	     = "CIS Az 7.5 - Check if Approved Extensions Are Installed"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Remove-AzVMExtension -ResourceGroupName <ResourceGroupName> -Name <ExtensionName> -VMName <VirtualMachineName>'
		DefaultValue	 = "By default, no extensions are added to the virtual machines."
		ExpectedValue    = "Only approved Extensions"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Virtual machine extensions and features for Windows'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/features-windows' })
	}
	return $inspectorobject
}

function Audit-CISAz75
{
	try
	{
		
		$Violation = @()

		$AzVMs = Get-AzVM
		foreach ($AzVM in $AzVMs){
			$Extensions = Get-AzVMExtension -ResourceGroupName $AzVM.ResourceGroupName -VMName $AzVM.Name | Select-Object Name, ExtensionType, ProvisioningState
			foreach ($Extension in $Extensions){
				$Violation += "$($AzVM.Name): $($Extension.Name)"
			}
		}

		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz75($Violation)
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
return Audit-CISAz75