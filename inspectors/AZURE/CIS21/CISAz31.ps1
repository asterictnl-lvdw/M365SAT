# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Defender for Endpoint integration with Microsoft Defender for Cloud is selected
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31"
		FindingName	     = "CIS Az 3.1 - Setting: 'Secure transfer required' is not set to 'Enabled' for some StorageAccounts."
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client. Because Azure storage doesn’t support HTTPS for custom domain names, this option is not applied when using a custom domain name."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <name> -EnableHttpsTrafficOnly $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Security recommendations for Blob storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations#encryption-in-transit' })
	}
	return $inspectorobject
}

function Audit-CISAz31
{
	try
	{
		$violation = @()
		$settings = Get-AzStorageAccount | Select-Object StorageAccountName,ResourceGroupName,EnableHttpsTrafficOnly
		foreach ($value in $settings){
			if ($value.EnableHttpsTrafficOnly -eq $False){
				$violation += $value.StorageAccountName
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz31($violation)
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
return Audit-CISAz31