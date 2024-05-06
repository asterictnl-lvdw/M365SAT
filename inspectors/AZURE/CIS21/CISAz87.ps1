# Date: 25-1-2023087
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Private Endpoints are Used for Azure Key Vault
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz87($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz87"
		FindingName	     = "CIS Az 8.7 - Private Endpoints are not Used for Azure Key Vault"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Private endpoints will keep network requests to Azure Key Vault limited to the endpoints attached to the resources that are whitelisted to communicate with each other. Assigning the Key Vault to a network without an endpoint will allow other resources on that network to view all traffic from the Key Vault to its destination. In spite of the complexity in configuration, this is recommended for high security secrets."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Update-AzKeyVault -ResourceGroupName <RESOURCE GROUP NAME> -VaultName <KEY VAULT NAME> -EnableRbacAuthorization $True'
		DefaultValue	 = "By default, Private Endpoints are not enabled for any services within Azure."
		ExpectedValue    = "Private Endpoints are enabled for any services within Azure."
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'What is a private endpoint?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview' },
		@{ 'Name' = 'Use private endpoints for Azure Storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints' },
		@{ 'Name' = 'Integrate Key Vault with Azure Private Link'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/private-link-service?tabs=portal' },
		@{ 'Name' = 'Tutorial: Connect to a storage account using an Azure Private Endpoint'; 'URL' = 'https://learn.microsoft.com/en-us/azure/private-link/tutorial-private-endpoint-storage-portal?tabs=dynamic-ip' })
	}
	return $inspectorobject
}

function Audit-CISAz87
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$PrivateEndpointConnection = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $AzKeyVault.ResourceId
			if ([string]::IsNullOrEmpty($PrivateEndpointConnection)){
				$Violation += $AzKeyVault.VaultName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz87($Violation)
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
return Audit-CISAz87