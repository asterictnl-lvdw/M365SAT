# Date: 25-1-2023085
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure the Key Vault is Recoverable
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz85($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz85"
		FindingName	     = "CIS Az 8.5 - Some Key Vaults are not Recoverable"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "There could be scenarios where users accidentally run delete/purge commands on Key Vault or an attacker/malicious user deliberately does so in order to cause disruption. Deleting or purging a Key Vault leads to immediate data loss, as keys encrypting data and secrets/certificates allowing access/services will become non-accessible. There is a Key Vault property that plays a role in permanent unavailability of a Key Vault: enablePurgeProtection: Setting this parameter to 'true' for a Key Vault ensures that even if Key Vault is deleted, Key Vault itself or its objects remain recoverable for the next 90 days. Key Vault/objects can either be recovered or purged (permanent deletion) during those 90 days. If no action is taken, the key vault and its objects will subsequently be purged. Enabling the enablePurgeProtection parameter on Key Vaults ensures that Key Vaults and their objects cannot be deleted/purged permanently."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Update-AzKeyVault -VaultName <vaultName -ResourceGroupName <resourceGroupName> -EnablePurgeProtection'
		DefaultValue	 = "enableSoftDelete: null enablePurgeProtection: null"
		ExpectedValue    = "enableSoftDelete: true enablePurgeProtection: true"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Azure Key Vault soft-delete overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview' })
	}
	return $inspectorobject
}

function Audit-CISAz85
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
			if ($KeyVaultDetails.EnablePurgeProtection -ne $True -or $KeyVaultDetails.EnableSoftDelete -ne $True){
				$Violation += $AzKeyVault.VaultName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz85($Violation)
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
return Audit-CISAz85