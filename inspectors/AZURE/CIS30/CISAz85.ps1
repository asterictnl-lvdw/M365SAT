# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz85($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz85"
		FindingName	     = "CIS Az 8.5 - Some 'Disk Network Access' is set to 'Enable public access from all networks'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "The setting 'Enable public access from all networks' is, in many cases, an overly permissive setting on Virtual Machine Disks that presents atypical attack, data infiltration, and data exfiltration vectors. If a disk to network connection is required, the	preferred setting is to 'Disable public access and enable private access.'"
		Remediation	     = "Use the below script to mitigate the issue"
		PowerShellScript = 'Update-AzDisk -ResourceGroup <resource group name> -DiskName $disk.Name -Disk $disk'
		DefaultValue	 = "By default, Disk Network access is set to Enable public access from all networks."
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Restrict import/export access for managed disks using Azure Private Link'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/disks-enable-private-links-for-import-export-portal' },
		@{ 'Name' = 'Azure CLI - Restrict import/export access for managed disks with Private Links'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-export-import-private-links-cli' },
		@{ 'Name' = 'Restrict managed disks from being imported or exported'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/disks-restrict-import-export-overview' })
	}
	return $inspectorobject
}

function Audit-CISAz85
{
	try
	{
		
		$Violation = @()
		$Disks = Get-AzDisk 
		foreach ($Disk in $Disks){
			if ($Disk.PublicNetworkAccess -eq "Enabled" -or $Disk.NetworkAccessPolicy -ne 'AllowPrivate' -or $Disk.NetworkAccessPolicy -ne 'DenyAll'){
				$Violation += $Disk.Name
			}
		}
			
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz85($Violation)
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
return Audit-CISAz85