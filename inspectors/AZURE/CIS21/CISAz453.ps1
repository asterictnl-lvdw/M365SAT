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


function Build-CISAz453($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz453"
		FindingName	     = "CIS Az 4.5.3 - Entra ID Client Authentication and Azure RBAC is not used where possible"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Entra ID client authentication is considerably more secure than token-based authentication because the tokens must be persistent at the client. Entra ID does not require this."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzCosmosDBAccount -ResourceGroupName resourceGroupName -Name accountName -EnableVirtualNetwork 1 '
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Azure role-based access control in Azure Cosmos DB'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/role-based-access-control' })
	}
	return $inspectorobject
}

function Audit-CISAz453
{
	try
	{
		$violation = @()
		# Script is unavailable at this time and will be fixed in future release
		<#
		$CosmosDBDatabases = Get-AzCosmosDBSqlDatabase
		
		foreach ($CosmosDBDatabase in $CosmosDBDatabases){
			$Account = Get-AzCosmosDBAccount -ResourceGroupName $CosmosDBDatabase.Resource -Name $CosmosDBDatabase.Name
			if ($Account.IsVirtualNetworkFilterEnabled -eq $false){
				$violation += $CosmosDBDatabase.Name
			}
		}
		#>
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz453($violation)
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
return Audit-CISAz453