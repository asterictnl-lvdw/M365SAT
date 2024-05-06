# Date: 25-1-2023088
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Private Endpoints are Used for Azure Key Vault
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz88($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz88"
		FindingName	     = "CIS Az 8.8 - Private Endpoints are not Used for Azure Key Vault"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Once set up, Automatic Private Key Rotation removes the need for manual administration when keys expire at intervals determined by your organization's policy. The recommended key lifetime is 2 years. Your organization should determine its own key expiration policy."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Update-AzKeyVault -ResourceGroupName <RESOURCE GROUP NAME> -VaultName <KEY VAULT NAME> -EnableRbacAuthorization $True'
		DefaultValue	 = "By default, Automatic Key Rotation is not enabled."
		ExpectedValue    = "Automatic Key Rotation is enabled."
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Configure cryptographic key auto-rotation in Azure Key Vault'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation' })
	}
	return $inspectorobject
}

function Audit-CISAz88
{
	try
	{
		
		$Violation = @()
		$AzKeyVaults = Get-AzKeyVault -ErrorAction SilentlyContinue
		foreach ($AzKeyVault in $AzKeyVaults){
			$AzKeys = Get-AzKeyVaultKey -VaultName $AzKeyVault.VaultName -ErrorAction SilentlyContinue
			foreach ($AzKey in $AzKeys){
				$RotationPolicy = Get-AzKeyVaultKeyRotationPolicy -VaultName $AzKeyVault.VaultName -Name $AzKey.Name -ErrorAction SilentlyContinue
				if ([string]::IsNullOrEmpty($RotationPolicy)){
					$Violation += $AzKeyVault.VaultName
				}
			}
			if ([string]::IsNullOrEmpty($PrivateEndpointConnection)){
				$Violation += $AzKeyVault.VaultName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz88($Violation)
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
return Audit-CISAz88