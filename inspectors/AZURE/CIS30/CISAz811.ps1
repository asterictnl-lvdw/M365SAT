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


function Build-CISAz811($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz811"
		FindingName	     = "CIS Az 8.11 - Trusted Launch is disabled on Virtual Machines"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Secure Boot and vTPM work together to protect your VM from a variety of boot attacks, including bootkits, rootkits, and firmware rootkits. Not enabling Trusted Launch in Azure VM can lead to increased vulnerability to rootkits and boot-level malware, reduced ability to detect and prevent unauthorized changes to the boot process, and a potential	compromise of system integrity and data security."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Set-AzVMSecurityProfile -VM $VM -SecurityType "<TrustedLaunch/ConfidentialVM>"'
		DefaultValue	 = "No Encryption"
		ExpectedValue    = "Encryption"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Enable Trusted launch on existing Azure VMs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-existing-vm?tabs=portal' },
		@{ 'Name' = 'Secure Boot'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch#secure-boot' })
	}
	return $inspectorobject
}

function Audit-CISAz811
{
	try
	{
		
		$Violation = @()
		$AzVMs = Get-AzVM | Select-Object Name, SecurityProfile
		foreach ($AzVM in $AzVMs){
			if ($null -eq $AzVM.SecurityProfile.SecurityType -or $AzVm.SecurityProfile.SecurityType -eq "Standard"){
				$Violation += $AzVM.Name
			}
		}
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz82($Violation)
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
return Audit-CISAz811