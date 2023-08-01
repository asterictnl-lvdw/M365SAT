# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Checks multiple storage accounts and executes various checks onto them. Not all CISAz can be targeted because there is not script available
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz300($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz300"
		FindingName	     = "CIS Az 3.x.x - Multiple Incompliant Storage Account Settings"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "9.8"
		Description	     = "M365SAT Found multiple incompliant Storage Account Settings. Please review them and take responsible actions to enhance security."
		Remediation	     = "Use the PowerShell Command to modify base settings"
		PowerShellScript = '$StorageAccounts = Get-AzStorageAccount | Select-Object ResourceGroupName, StorageAccountName ; ForEach ($StorageAccount in $StorageAccounts){ Set-AzStorageAccount -ResourceGroupName $StorageAccount.ResourceGroupName -Name $StorageAccount.StorageAccountName -PublicNetworkAccess "$null" -KeyExpirationPeriodInDay -MinimumTlsVersion "TLS1_2" -EnableHttpsTrafficOnly $True }'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "Critical"
		RiskRating	     = "Crticial"
		References	     = @(@{ 'Name' = 'Set-StorageAccount'; 'URL' = 'https://learn.microsoft.com/en-us/powershell/module/az.storage/set-azstorageaccount?view=azps-9.6.0&viewFallbackFrom=azps-9.7.1' })
	}
	return $inspectorobject
}

function Audit-CISAz300
{
	try
	{
		$Settings = Get-AzStorageAccount | Select-Object * -ExpandProperty Encryption | Select-Object * -ExpandProperty NetworkRuleSet | Select-Object KeySource, StorageAccountName, ResourceGroupName, MinimumTLSVersion, EnableHttpsTrafficOnly, PublicNetworkAccess, DefaultAction, Bypass
		
		if ($Settings.enabled -eq $False)
		{
			$finalobject = Build-CISAz300($Settings.enabled)
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
return Audit-CISAz300