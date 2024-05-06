# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that `Allow Blob Anonymous Access` is set to `Disabled` (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz317($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz317"
		FindingName	     = "CIS Az 3.17 - Some Azure Storage Accounts have their 'Allow Blob Anonymous Access' set to Enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "If 'Allow Blob Anonymous Access' is enabled, blobs can be accessed by adding the blob name to the URL to see the contents. An attacker can enumerate a blob using methods, such as brute force, and access them. Exfiltration of data by brute force enumeration of items from a storage account may occur if this setting is set to 'Enabled"
		Remediation	     = "You can change the settings in the by executing the written PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -allowCrossTenantReplication $false'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Remediate anonymous read access to blob data (Azure Resource Manager deployments)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent?tabs=portal' },
		@{ 'Name' = 'Remediate anonymous read access to blob data (classic deployments)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent-classic?tabs=portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz317
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount
		foreach ($StorageAccount in $StorageAccounts){
			if ($StorageAccount.AllowBlobPublicAccess -eq $true){
				$violation += $StorageAccount.StorageAccountName
			}
		}
		$violation

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz317($violation)
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
return Audit-CISAz317