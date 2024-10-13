# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Enable Role Based Access Control for Azure Key Vault
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz336($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz336"
		FindingName	     = "CIS Az 3.3.6 - Role Based Access Control for Azure Key is not Enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "The new RBAC permissions model for Key Vaults enables a much finer grained access control for key vault secrets, keys, certificates, etc., than the vault access policy. This in turn will permit the use of privileged identity management over these roles, thus securing the key vaults with JIT Access management."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzKeyVault -ResourceGroupName <RESOURCE GROUP NAME> -VaultName <KEY VAULT NAME> -EnableRbacAuthorization $True'
		DefaultValue	 = "EnableRbacAuthorization: False"
		ExpectedValue    = "EnableRbacAuthorization: True"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Vault access policy to Azure RBAC migration steps'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/key-vault/general/rbac-migration#vault-access-policy-to-azure-rbac-migration-steps' },
		@{ 'Name' = 'Assign Azure roles using the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/role-based-access-control/role-assignments-portal?tabs=current' },
		@{ 'Name' = 'What is Azure role-based access control (Azure RBAC)?'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/role-based-access-control/overview' },
		@{ 'Name' = 'DP-8: Ensure security of key and certificate repository'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-8-ensure-security-of-key-and-certificate-repository' })
	}
	return $inspectorobject
}

function Audit-CISAz336
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault
		foreach ($AzKeyVault in $AzKeyVaults){
			$KeyVaultDetails = Get-AzKeyVault -VaultName $AzKeyVault.VaultName
			if ($KeyVaultDetails.EnableRbacAuthorization -ne $true){	
				$Violation += $AzKeyVault.VaultName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz336($Violation)
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
return Audit-CISAz336