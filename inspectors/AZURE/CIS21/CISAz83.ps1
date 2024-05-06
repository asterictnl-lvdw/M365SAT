# Date: 25-1-2023083
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that the Expiration Date is set for all Secrets in RBAC Key Vaults
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz83($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz83"
		FindingName	     = "CIS Az 8.3 - Expiration Date is not set for all Secrets in RBAC Key Vaults"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "The Azure Key Vault enables users to store and keep secrets within the Microsoft Azure environment. Secrets in the Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The exp (expiration date) attribute identifies the expiration date on or after which the secret MUST NOT be used. By default, secrets never expire. It is thus recommended to rotate secrets in the key vault and set an explicit expiration date for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Set-AzKeyVaultSecretAttribute -VaultName <Vault Name> -Name <Secret Name> -Expires <DateTime>'
		DefaultValue	 = "No Expiration"
		ExpectedValue    = "An Expiration Date + Time"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Azure Key Vault basic concepts'; 'URL' = 'https://docs.microsoft.com/en-us/azure/key-vault/key-vault-whatis' })
	}
	return $inspectorobject
}

function Audit-CISAz83
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
			if ($KeyVaultDetails.EnableRbacAuthorization -eq $True){
				$KeyVaultSecret = Get-AzKeyVaultSecret -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
				if ([string]::IsNullOrEmpty($KeyVaultSecret.Expires) -or $KeyVaultSecret.Enabled -eq $true){
					$Violation += $AzKeyVault.VaultName
				}
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz83($Violation)
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
return Audit-CISAz83