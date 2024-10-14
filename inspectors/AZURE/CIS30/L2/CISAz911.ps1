# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz911($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz911"
		FindingName	     = "CIS Az 9.1.1 - Azure Key Vaults are not Used to Store Secrets"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "The credentials given to an application have permissions to create, delete, or modify data stored within the systems they access. If these credentials are stored within the application itself, anyone with access to the application or a copy of the code has access to them. Storing within Azure Key Vault as secrets increases security by controlling access. This also allows for updates of the credentials without redeploying the entire application."
		Remediation	     = "Use the PowerShell Script and change the expiration date to the desired value"
		PowerShellScript = 'New-AzKeyvault -name <name> -ResourceGroupName <myResourceGroup> -Location <myLocation>'
		DefaultValue	 = "By default, no Azure Key Vaults are created."
		ExpectedValue    = "An active used KeyVault"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Use Key Vault references as app settings in Azure App Service and Azure Functions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references?tabs=azure-cli' },
		@{ 'Name' = 'IM-3: Manage application identities securely and automatically'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-3-manage-application-identities-securely-and-automatically' })
	}
	return $inspectorobject
}

function Audit-CISAz911
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
			$KeyVaultSecret = Get-AzKeyVaultSecret -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
				if ([string]::IsNullOrEmpty($KeyVaultSecret) -or $KeyVaultSecret.Enabled -ne $true){
					$Violation += "No KeyVault Secrets in KeyVault stored."
				}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz911($Violation)
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
return Audit-CISAz911