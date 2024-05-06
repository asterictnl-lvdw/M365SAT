# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Cross Tenant Replication' is not enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz316($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz316"
		FindingName	     = "CIS Az 3.16 - 'Cross Tenant Replication' is enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Disabling Cross Tenant Replication minimizes the risk of unauthorized data access and ensures that data governance policies are strictly adhered to. This control is especially critical for organizations with stringent data security and privacy requirements, as it prevents the accidental sharing of sensitive information."
		Remediation	     = "You can change the settings in the by executing the written PowerShellScript."
		PowerShellScript = 'Set-AzStorageAccount -ResourceGroupName <resource group name> -Name <storage account name> -allowCrossTenantReplication $false'
		DefaultValue	 = "Enabled on accounts before Dec 15 2023, else disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Prevent object replication across Microsoft Entra tenants'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/blobs/object-replication-prevent-cross-tenant-policies?tabs=portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz316
{
	try
	{
		$violation = @()
		$StorageAccounts = Get-AzStorageAccount
		foreach ($StorageAccount in $StorageAccounts){
			if ($StorageAccount.AllowCrossTenantReplication -ne $false){
				$violation += $StorageAccount.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz316($violation)
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
return Audit-CISAz316