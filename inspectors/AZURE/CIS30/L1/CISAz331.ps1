# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that the Expiration Date is set for all Keys in RBAC Key Vaults
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz331($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz331"
		FindingName	     = "CIS Az 3.3.1 - Expiration Date is not set for all Keys in RBAC Key Vaults"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The exp (expiration date) attribute identifies the expiration date on or after which the key MUST NOT be used for encryption of new data, wrapping of new keys, and signing. By default, keys never expire. It is thus recommended that keys be rotated in the key vault and set an explicit expiration date for all keys to help enforce the key rotation. This ensures that the keys cannot be used beyond their assigned lifetimes"
		Remediation	     = "Use the PowerShell Script and change the expiration date to the desired value"
		PowerShellScript = 'Set-AzKeyVaultKeyAttribute -VaultName <VaultName> -Name <KeyName> -Expires <DateTime>'
		DefaultValue	 = "No Expiration"
		ExpectedValue    = "An Expiration Date + Time"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Azure Key Vault basic concepts'; 'URL' = 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis' },
		@{ 'Name' = 'Azure Key Vault keys, secrets and certificates overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates#key-vault-keys' },
		@{ 'Name' = 'DP-6: Use a secure key management process'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-6-use-a-secure-key-management-process' })
	}
	return $inspectorobject
}

function Audit-CISAz331
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
			if ($KeyVaultDetails.EnableRbacAuthorization -eq $true){
				$KeyVaultKey = Get-AzKeyVaultKey -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
				if ([string]::IsNullOrEmpty($KeyVaultKey.Expires) -or $KeyVaultKey.Enabled -eq $true){
					$Violation += $AzKeyVault.VaultName
				}
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz331($Violation)
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
return Audit-CISAz331