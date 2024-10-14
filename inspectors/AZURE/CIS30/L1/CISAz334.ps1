# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz334($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz334"
		FindingName	     = "CIS Az 3.3.4 - Expiration Date is not set for all Secrets in Non-RBAC Key Vaults"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The exp (expiration date) attribute identifies the expiration date on or after which the secret MUST NOT be used. By default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration date for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes."
		Remediation	     = "Use the PowerShell Script and change the expiration date to the desired value"
		PowerShellScript = 'Set-AzKeyVaultSecret -VaultName <Vault Name> -Name <Secret Name> -Expires <DateTime>'
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

function Audit-CISAz334
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
			if ($KeyVaultDetails.EnableRbacAuthorization -eq $False){
				$KeyVaultSecret = Get-AzKeyVaultSecret -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
				if ([string]::IsNullOrEmpty($KeyVaultSecret.Expires) -or $KeyVaultSecret.Enabled -eq $true){
					$Violation += $AzKeyVault.VaultName
				}
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz334($Violation)
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
return Audit-CISAz334