# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'Firewalls & Networks' Is Limited to Use Selected Networks Instead of All Networks (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz451($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz451"
		FindingName	     = "CIS Az 4.5.1 - 'Firewalls & Networks' Is not Limited to Use Selected Networks Instead of All Networks"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Selecting certain networks for your Cosmos DB to communicate restricts the number of networks including the internet that can interact with what is stored within the database and limiting your Cosmos DB to only communicate on whitelisted networks lowers its attack footprint."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzCosmosDBAccount -ResourceGroupName resourceGroupName -Name accountName -EnableVirtualNetwork 1 '
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure Azure Private Link for an Azure Cosmos DB account'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-private-endpoints?tabs=arm-bicep' },
		@{ 'Name' = 'Configure access to Azure Cosmos DB from virtual networks (VNet)'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-vnet-service-endpoint' })
	}
	return $inspectorobject
}

function Audit-CISAz451
{
	try
	{
		$violation = @()
		$AzResources = Get-AzResource | Select-Object ResourceGroupName -Unique
		foreach ($Resource in $AzResources){
			$AzCosmosDBAccounts = Get-AzCosmosDBAccount -ResourceGroupName $Resource.ResourceGroupName
			foreach ($AzCosmosDBAccount in $AzCosmosDBAccounts){
				$Account = Get-AzCosmosDBAccount -ResourceGroupName $Resource.ResourceGroupName -Name $AzCosmosDBAccount.Name
				if ($Account.IsVirtualNetworkFilterEnabled -eq $false){
					$violation += $CosmosDBDatabase.Name
				}
			}
		}
		

		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz451($violation)
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
return Audit-CISAz451