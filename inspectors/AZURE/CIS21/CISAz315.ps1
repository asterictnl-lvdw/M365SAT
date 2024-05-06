# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure the "Minimum TLS version" for storage accounts is set to "Version 1.2"
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz315($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz315"
		FindingName	     = "CIS Az 3.15 - The Minimum TLS version for some storage accounts is not set to minimum Version 1.2"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "TLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS protocol. Continued use of this legacy protocol affects the security of data in transit."
		Remediation	     = "You can change the settings in the by executing the written PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -MinimumTlsVersion TLS1_2'
		DefaultValue	 = "TLS1_2 if created via portal. Else TLS1_0"
		ExpectedValue    = "TLS1_2"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Enforce a minimum required version of Transport Layer Security (TLS) for requests to a storage account'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version?tabs=portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz315
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount
		foreach ($StorageAccount in $StorageAccounts){
			if ($StorageAccount.MinimumTlsVersion -ne "TLS1_2"){
				$violation += $StorageAccount.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz315($violation)
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
return Audit-CISAz315