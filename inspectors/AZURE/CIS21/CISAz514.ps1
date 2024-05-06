# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz514($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz514"
		FindingName	     = "CIS Az 5.1.4 - Logging for Azure Key Vault is not 'Enabled'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Monitoring how and when key vaults are accessed, and by whom, enables an audit trail of interactions with confidential information, keys, and certificates managed by Azure Key Vault. Enabling logging for Key Vault saves information in a user provided destination of either an Azure storage account or Log Analytics workspace. The same destination can be used for collecting logs for multiple Key Vaults."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzDiagnosticSetting'
		DefaultValue	 = "KeySource: Microsoft.Storage"
		ExpectedValue    = "KeySource: Microsoft.Keyvault"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Enable Key Vault logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/key-vault/general/howto-logging?tabs=azure-cli' })
	}
	return $inspectorobject
}

function Audit-CISAz514
{
	try
	{
		$Violation = @()
		$KeyVaults = Get-AzKeyVault
		foreach ($KeyVault in $KeyVaults){
			try{
				$DiagSetting = Get-AzDiagnosticSetting -ResourceId $KeyVault.Id
				if ([string]::IsNullOrEmpty($DiagSetting) -or $DiagSetting.Log.Enabled -eq $False -or $DiagSetting.Log.CategoryGroup -notlike "audit" -or $DiagSetting.Log.CategoryGroup -notlike "allLogs"){
					$Violation += $KeyVault.VaultName
				}
			}catch{
				continue
			}
		}
	
		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz514($violation)
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
return Audit-CISAz514