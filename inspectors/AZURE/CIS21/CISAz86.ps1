# Date: 25-1-2023086
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Enable Role Based Access Control for Azure Key Vault
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz86($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz86"
		FindingName	     = "CIS Az 8.6 - Role Based Access Control for Azure Key is not Enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "The new RBAC permissions model for Key Vaults enables a much finer grained access control for key vault secrets, keys, certificates, etc., than the vault access policy. This in turn will permit the use of privileged identity management over these roles, thus securing the key vaults with JIT Access management."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Update-AzKeyVault -ResourceGroupName <RESOURCE GROUP NAME> -VaultName <KEY VAULT NAME> -EnableRbacAuthorization $True'
		DefaultValue	 = "EnableRbacAuthorization: False"
		ExpectedValue    = "EnableRbacAuthorization: True"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'What is Azure role-based access control (Azure RBAC)?'; 'URL' = 'https://learn.microsoft.com/en-gb/azure/role-based-access-control/overview' })
	}
	return $inspectorobject
}

function Audit-CISAz86
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
			$finalobject = Build-CISAz86($Violation)
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
return Audit-CISAz86