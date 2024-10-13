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


function Build-CISAz88($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz88"
		FindingName	     = "CIS Az 8.8 - Endpoint Protection for all Virtual Machines is not installed"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Installing endpoint protection systems (like anti-malware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. These also offer configurable alerts when known-malicious or unwanted software attempts to install itself or run on Azure systems."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Remove-AzVMExtension -ResourceGroupName <ResourceGroupName> -Name <ExtensionName> -VMName <VirtualMachineName>'
		DefaultValue	 = "By default Endpoint Protection is disabled."
		ExpectedValue    = "Endpoint Protection is enabled."
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Containers support matrix in Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/support-matrix-defender-for-containers?tabs=features-windows#supported-endpoint-protection-solutions-' },
		@{ 'Name' = 'Microsoft Antimalware for Azure Cloud Services and Virtual Machines'; 'URL' = 'https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware' },
		@{ 'Name' = 'ES-1: Use Endpoint Detection and Response (EDR)'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-1-use-endpoint-detection-and-response-edr' })
	}
	return $inspectorobject
}

function Audit-CISAz88
{
	try
	{
		$Violation = @()
		$AzVMs = Get-AzVM
		foreach ($AzVM in $AzVMs){
			$Check = Get-AzAdvisorRecommendation -ResourceId $AzVM.Id | Where-Object {$_.ImpactedField -eq "Microsoft.Compute/virtualMachines" -and $_.Category -eq "Security" -and $_.ShortDescriptionProblem.Contains("EDR solution should be installed on Virtual Machines")}
			#EDR solution should be installed on Virtual machines has an ID of 06e3a6db-6c0c-4ad9-943f-31d9d73ecf6c
			if ($Check.RecommendationTypeId -eq "06e3a6db-6c0c-4ad9-943f-31d9d73ecf6c"){
				$Violation += $AzVM.Name
			}
		}
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz88($Violation)
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
return Audit-CISAz88