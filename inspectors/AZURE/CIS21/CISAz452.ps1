# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure That Private Endpoints Are Used Where Possible (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz452($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz452"
		FindingName	     = "CIS Az 4.5.2 - Private Endpoints Are Not Used Where Possible with Cosmos DBs"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "For sensitive data, private endpoints allow granular control of which services can communicate with Cosmos DB and ensure that this network traffic is private. You set this up on a case by case basis for each service you wish to be connected."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlServer -ResourceGroupName <server>.ResourceGroupName -Name <Server>.Name -ssl-enforcement Enabled'
		DefaultValue	 = "By default Cosmos DB does not have private endpoints enabled and its traffic is public to the network."
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

function Audit-CISAz452
{
	try
	{
		$violation = @()
		# Script is unavailable and will be fixed in the future
		<#
		$CosmosDBDatabases = Get-AzCosmosDBSqlDatabase
		
		foreach ($CosmosDBDatabase in $CosmosDBDatabases){
			Get-AzPrivateEndpointConnection -PrivateLinkResourceId $CosmosDBDatabase.Id -ResourceGroupName $CosmosDBDatabase.Resource -Name
			$Account = Get-AzCosmosDBAccount -ResourceGroupName $CosmosDBDatabase.Resource -Name $CosmosDBDatabase.Name
			if ($Account.IsVirtualNetworkFilterEnabled -eq $false){
				$violation += $CosmosDBDatabase.Name
			}
		}

		$violation
		#>

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz452($violation)
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
return Audit-CISAz452