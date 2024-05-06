# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure additional storage providers are restricted in Outlook on the web
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx650($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx650"
		FindingName	     = "CIS MEx 6.5 - Additional storage providers are not restricted in Outlook on the Web"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "15"
		Description	     = "By default additional storage providers are allowed in Office on the Web (such as Box, Dropbox, Facebook, Google Drive, OneDrive Personal, etc.). This could lead to information leakage and additional risk of infection from organizational non-trusted storage providers. Restricting this will inherently reduce risk as it will narrow opportunities for infection and data leakage."
		Remediation	     = "Use the PowerShell Script to remediate this issue. You can check with the PowerShell command: <b>Get-OwaMailboxPolicy | Format-Table Name, AdditionalStorageProvidersAvailable</b> if the remediation has been successful!"
		PowerShellScript = 'Set-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default -AdditionalStorageProvidersAvailable $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = '3rd party cloud storage services supported by Office apps'; 'URL' = 'https://support.microsoft.com/en-us/topic/3rd-party-cloud-storage-services-supported-by-office-apps-fce12782-eccc-4cf5-8f4b-d1ebec513f72' })
	}
	return $inspectorobject
}

function Audit-CISMEx650
{
	try
	{
		$AdditionalStorageProvidersAvailable = Get-OwaMailboxPolicy | Select-Object Name, AdditionalStorageProvidersAvailable
		$PolicyViolation = @()
		foreach ($Policy in $AdditionalStorageProvidersAvailable)
		{
			if ($AdditionalStorageProvidersAvailable.AdditionalStorageProvidersAvailable -match 'True')
			{
				$PolicyViolation += "$($Policy.Name): AdditionalStorageProvidersAvailable: $($AdditionalStorageProvidersAvailable.AdditionalStorageProvidersAvailable)"
			}
		}
		if ($PolicyViolation.count -igt 0)
		{
			
			$finalobject = Build-CISMEx650($PolicyViolation)
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
return Audit-CISMEx650