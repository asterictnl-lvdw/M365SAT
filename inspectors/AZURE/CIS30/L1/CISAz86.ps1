# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz86($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz86"
		FindingName	     = "CIS Az 8.6 - 'Enable Data Access Authentication Mode' is not 'Checked'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Enabling data access authentication mode adds a layer of protection using an Entra ID role to further restrict users from creating and using Secure Access Signature (SAS) tokens for exporting a detached managed disk or virtual machine state. Users will need the Data operator for managed disk role within Entra ID in order to download a VHD or VM Guest state using a secure URL."
		Remediation	     = "Use the below script to mitigate the issue"
		PowerShellScript = 'Get-AzDisk | Update-AzDisk -ResourceGroup $_.Resource -DiskName $disk.Name -Disk $disk'
		DefaultValue	 = "By default, Data Access Authentication Mode is Disabled."
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Secure downloads and uploads with Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/azure/virtual-machines/windows/download-vhd?tabs=azure-portal#secure-downloads-and-uploads-with-microsoft-entra-id' })
	}
	return $inspectorobject
}

function Audit-CISAz86
{
	try
	{
		
		$Violation = @()
		$Disks = Get-AzDisk 
		foreach ($Disk in $Disks){
			if ([string]::IsNullOrEmpty($Disk.DataAccessAuthMode) -or -not $Disk.DataAccessAuthMode.Contains("AzureActiveDirectory")){
				$Violation += $Disk.Name
			}
		}
			
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz86($Violation)
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
return Audit-CISAz86