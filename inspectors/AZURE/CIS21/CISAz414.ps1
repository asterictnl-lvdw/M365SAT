# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Entra authentication is Configured for SQL Servers (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz414($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz414"
		FindingName	     = "CIS Az 4.1.4 - Microsoft Entra authentication is not Configured for SQL Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Microsoft Entra authentication is a mechanism to connect to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in the Microsoft Entra ID directory. With Entra ID authentication, identities of database users and other Microsoft services can be managed in one central location. Central ID management provides a single place to manage database users and simplifies permission management."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName <resource group name> -ServerName <server name> -DisplayName <Display name of AD account to set as DB administrator>'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure and manage Microsoft Entra authentication with Azure SQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?view=azuresql&tabs=azure-powershell' },
		@{ 'Name' = 'Use Microsoft Entra authentication'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-overview?view=azuresql' },
		@{ 'Name' = 'Azure Key Vault basic concepts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts' })
	}
	return $inspectorobject
}

function Audit-CISAz414
{
	try
	{
		$violation = @()
		$SQLServers = Get-AzSqlServer
		foreach ($SQLServer in $SQLServers){
			$Server = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName
			if ($Server.IsAzureADOnlyAuthentication -eq $false){
				$violation += $SQLServer.ServerName
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz414($violation)
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
return Audit-CISAz414