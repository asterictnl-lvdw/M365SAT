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


function Build-CISAz513($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz513"
		FindingName	     = "CIS Az 5.1.3 - Some storage accounts containing containers with activity logs are not encrypted with Customer Managed Keys (CMK)"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Configuring the storage account with the activity log export container to use CMKs provides additional confidentiality controls on log data, as a given user must have read permission on the corresponding storage account and must be granted decrypt permission by the CMK."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Set-AzStorageAccount'
		DefaultValue	 = "KeySource: Microsoft.Storage"
		ExpectedValue    = "KeySource: Microsoft.Keyvault"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Managing legacy log profiles'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log?tabs=cli#managing-legacy-log-profiles' })
	}
	return $inspectorobject
}

function Audit-CISAz513
{
	try
	{
		$Violation = @()
		$context = Get-AzContext
		$storageAccounts = Get-AzStorageAccount
		foreach ($storageAccount in $storageAccounts){
			if ([string]::IsNullOrEmpty($storageAccount.Encryption.KeyVaultProperties) -or $storageAccount.Encryption.KeySource -eq "Microsoft.Storage"){
				$Violation += $storageAccount.Name
			}
		}
	

		if ($Violation.count -igt 0){
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