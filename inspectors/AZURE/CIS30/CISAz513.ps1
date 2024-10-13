# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz513($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz513"
		FindingName	     = "CIS Az 5.1.3 - Some SQL server's Transparent Data Encryption (TDE) protector are not encrypted with Customer-managed key"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system, is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzSqlServerTransparentDataEncryptionProtector -Type AzureKeyVault -KeyId <KeyIdentifier> -ServerName <ServerName> -ResourceGroupName <ResourceGroupName>'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Azure SQL transparent data encryption with customer-managed key'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-byok-overview?view=azuresql' },
		@{ 'Name' = 'Databases (Preview)'; 'URL' = 'https://azure.microsoft.com/en-us/blog/category/databases/' },
		@{ 'Name' = 'Deploying a Key Vault-based TDE protector for Azure SQL'; 'URL' = 'https://winterdom.com/2017/09/07/azure-sql-tde-protector-keyvault' },
		@{ 'Name' = 'DP-5: Use customer-managed key option in data at rest encryption when required'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-5-use-customer-managed-key-option-in-data-at-rest-encryption-when-required' },
		@{ 'Name' = 'Azure Key Vault basic concepts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/basic-concepts' })
	}
	return $inspectorobject
}

function Audit-CISAz513
{
	try
	{
		$violation = @()
		$SQLServers = Get-AzSqlServer
		foreach ($SQLServer in $SQLServers){
			$Server = Get-AzSqlServerTransparentDataEncryptionProtector -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName
			if ($Server.Type -ne "AzureKeyVault" -or $Server.ServerKeyVaultKeyName -ne "KeyVaultName_KeyName_KeyIdentifierVersion" -or $Server.KeyId -ne "KeyIdentifier"){
				$violation += $SQLServer.ServerName
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz513($violation)
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
return Audit-CISAz513