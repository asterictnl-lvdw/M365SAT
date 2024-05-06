# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Public Network Access' is `Disabled' for storage accounts (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz37($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz37"
		FindingName	     = "CIS Az 3.7 - 'Public access level' is enabled for some storage accounts"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "The default configuration for a storage account permits a user with appropriate permissions to configure public (anonymous) access to containers and blobs in a storage account. Keep in mind that public access to a container is always turned off by default and must be explicitly configured to permit anonymous requests. It grants readonly access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide anonymous access to blob containers until, and unless, it is strongly desired. A shared access signature token or Azure AD RBAC should be used for providing controlled and timed access to blob containers. If no anonymous access is needed on any container in the storage account, it’s recommended to set allowBlobPublicAccess false at the account level, which forbids any container to accept anonymous access in the future."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -PublicNetworkAccess Disabled'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure anonymous read access for containers and blobs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure?tabs=portal' },
		@{ 'Name' = 'Assign an Azure role for access to blob data'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/assign-azure-role-data-access?tabs=portal' },
		@{ 'Name' = 'Remediate anonymous read access to blob data (classic deployments)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent-classic?tabs=portal' },					
		@{ 'Name' = 'Remediate anonymous read access to blob data (Azure Resource Manager deployments)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent?tabs=portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz37
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName,ResourceGroupName,PublicNetworkAccess

		foreach ($StorageAccount in $StorageAccounts){
			if ($StorageAccount.PublicNetworkAccess -eq 'Enabled'){
				$violation += $context.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz37($violation)
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
return Audit-CISAz37