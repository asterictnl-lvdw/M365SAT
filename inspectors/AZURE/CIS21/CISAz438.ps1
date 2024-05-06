# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz438($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz438"
		FindingName	     = "CIS Az 4.3.8 - 'Allow access to Azure services' for some PostgreSQL Database Servers is not disabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "If Double Encryption is enabled, another layer of encryption is implemented at the hardware level before the storage or network level. Information will be encrypted before it is even accessed, preventing both interception of data in motion if the network layer encryption is broken and data at rest in system resources such as memory or processor cache. Encryption will also be in place for any backups taken of the database, so the key will secure access the data in all forms. For the most secure implementation of key based encryption, it is recommended to use a Customer Managed asymmetric RSA 2048 Key in Azure Key Vault."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name connection_throttling -Value on'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Infrastructure double encryption for Azure Database for PostgreSQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-double-encryption' },
		@{ 'Name' = 'Azure Database for PostgreSQL Infrastructure double encryption'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-infrastructure-double-encryption' },
		@{ 'Name' = 'Azure Database for PostgreSQL Single server data encryption with a customer-managed key'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-data-encryption-postgresql' },
		@{ 'Name' = 'Bring your own key specification'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification' })
	}
	return $inspectorobject
}

function Audit-CISAz438
{
	try
	{
		$violation = @()
		
		$PostGresServers = Get-AzPostgreSqlServer
		
		foreach ($PostGresServer in $PostGresServers){
			if ($PostGresServer.InfrastructureEncryption -eq $false){
				$violation += $PostGresServer.Name
			}
		}

		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz438($violation)
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
return Audit-CISAz438