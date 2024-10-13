# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz528($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz528"
		FindingName	     = "CIS Az 5.2.8 - 'Infrastructure double encryption' for some PostgreSQL single servers is 'Disabled'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "If Double Encryption is enabled, another layer of encryption is implemented at the hardware level before the storage or network level. Information will be encrypted before it is even accessed, preventing both interception of data in motion if the network layer encryption is broken and data at rest in system resources such as memory or processor cache. Encryption will also be in place for any backups taken of the database, so the key will secure access the data in all forms. For the most secure implementation of key based encryption, it is recommended to use a Customer Managed asymmetric RSA2048 Key in Azure Key Vault."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name infrastructureEncryption -Value enabled'
		DefaultValue	 = "By Default, Double Encryption is disabled."
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'What happens to Azure Database for PostgreSQL - Single Server after the retirement announcement?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/whats-happening-to-postgresql-single-server' },
		@{ 'Name' = 'What is the migration service in Azure Database for PostgreSQL?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/migrate/migration-service/overview-migration-service-postgresql' })
	}
	return $inspectorobject
}

function Audit-CISAz528
{
	try
	{
		$violation = @()
		$PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/servers'}
		foreach ($PostGreServer in $PostGreServers){
			$Configuration = Get-AzPostgreSqlServer -ResourceGroupName $PostGreServer.ResourceGroupName -Name $PostGreServer.Name
			if ($Configuration.InfrastructureEncryption -eq $false){
				$violation += $PostGreServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz528($violation)
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
return Audit-CISAz528