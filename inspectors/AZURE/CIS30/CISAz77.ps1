# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Network Security Group Flow Log retention period is not 'greater than 90 days'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz77($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz77"
		FindingName	     = "CIS Az 7.7 - Public IP addresses must be Evaluated on a Periodic Basis"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Public IP Addresses allocated to the tenant should be periodically reviewed for necessity. Public IP Addresses that are not intentionally assigned and controlled present a publicly facing vector for threat actors and significant risk to the tenant"
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = '-'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Security Control: Network security'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security' })
	}
	return $inspectorobject
}

function Audit-CISAz77
{
	try
	{
		
		$Addresses = @()
		
		$PublicIpAddresses = Get-AzPublicIpAddress
		foreach ($PublicIpAddress in $PublicIpAddresses){
			$Addresses += $AzNetworkWatcher.Name
		}
		
		
		if ($Violation.count -ne 0)
		{
			$finalobject = Build-CISAz77($Violation)
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
return Audit-CISAz77