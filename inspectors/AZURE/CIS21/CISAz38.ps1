# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Default Network Access Rule for Storage Accounts is Set to Deny
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz38($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz38"
		FindingName	     = "CIS Az 3.8 - Some Default Network Access Rules for Storage Accounts are not Set to Deny"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Storage accounts should be configured to deny access to traffic from all networks (including internet traffic). Access can be granted to traffic from specific Azure Virtual networks, allowing a secure network boundary for specific applications to be built.Access can also be granted to public internet IP address ranges to enable connections from specific internet or on-premises clients. When network rules are configured, only applications from allowed networks can access a storage account. When calling from an allowed network, applications continue to require proper authorization (a valid access key or SAS token) to access the storage account."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -NetworkRuleSet Deny'
		DefaultValue	 = "Allow"
		ExpectedValue    = "Deny"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure Azure Storage firewalls and virtual networks'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz38
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount 
		ForEach ($Account in $StorageAccounts){
			$NetworkSetting = $Account | Get-AzStorageAccountNetworkRuleSet | Select-Object DefaultAction
			if ($NetworkSetting.DefaultAction -eq 'Allow'){
				$violation += $context.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz38($violation)
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
return Audit-CISAz38