# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose:  Ensure that Storage Account Access Keys are Periodically Regenerated
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz34($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz34"
		FindingName	     = "CIS Az 3.4 - Setting Some Storage Account Access Keys are not Periodically Regenerated"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "When a storage account is created, Azure generates two 512-bit storage access keys which are used for authentication when the storage account is accessed. Rotating these keys periodically ensures that any inadvertent access or exposure does not result from the compromise of these keys."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Get-AzStorageAccount | Set-AzStorageAccount -Name $_.StorageAccountName -KeyExpirationPeriodInDay 90'
		DefaultValue	 = "null"
		ExpectedValue    = "90"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Create a storage account'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?tabs=azure-portal#regenerate-storage-access-keys' },
		@{ 'Name' = 'PCI DSS Key Rotation Requirements'; 'URL' = 'https://pcidssguide.com/pci-dss-key-rotation-requirements/' },
		@{ 'Name' = 'NIST 800-57 Rev. 5 - Recommendation for Key Management'; 'URL' = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf' })
	}
	return $inspectorobject
}

function Audit-CISAz34
{
	try
	{
		$violation = @()
		$accounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
		ForEach ($account in $accounts){
			if ($account.KeyPolicy.KeyExpirationPeriodInDays -lt 90 -or $null -eq $account.KeyPolicy.KeyExpirationPeriodInDays){
				$violation += $account.StorageAccountName
			}elseif ($null -eq $account.KeyCreationTime.Key1 -or $null -eq $account.KeyCreationTime.Key2){
				$violation += $account.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz34($violation)
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
return Audit-CISAz34