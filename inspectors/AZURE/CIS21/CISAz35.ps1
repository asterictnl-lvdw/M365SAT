# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Storage Logging is Enabled for Queue Service for 'Read', 'Write', and 'Delete' requests
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz35($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz35"
		FindingName	     = "CIS Az 3.5 - Some Storage Logging is disabled for Queue Service for Read, Write and Delete Requests"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Storage Analytics logs contain detailed information about successful and failed requests to a storage service. This information can be used to monitor individual requests and to diagnose issues with a storage service. Requests are logged on a best-effort basis. Storage Analytics logging is not enabled by default for your storage account."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzStorageServiceLoggingProperty -ServiceType Queue -LoggingOperations read,write,delete -RetentionDays 90 -Context $MyContextObject'
		DefaultValue	 = "None"
		ExpectedValue    = "All"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Azure Storage analytics logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-analytics-logging' },
							@{ 'Name' = 'Monitor Azure Queue Storage'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/queues/monitor-queue-storage?tabs=azure-portal' })			
	}
	return $inspectorobject
}

function Audit-CISAz35
{
	try
	{
		$violation = @()
		$contexts = Get-AzStorageAccount -ErrorAction SilentlyContinue | Select-Object StorageAccountName,ResourceGroupName 
		foreach ($context in $contexts){
			try{
			$StorageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $context.ResourceGroupName -Name $context.StorageAccountName -ErrorAction SilentlyContinue).Value[0]
			$cont = New-AzStorageContext -StorageAccountName $context.StorageAccountName -StorageAccountKey $StorageAccountKey -ErrorAction SilentlyContinue
			$Logging = Get-AzStorageServiceLoggingProperty -ServiceType Queue -Context $cont -ErrorAction SilentlyContinue
			if ($Logging.LoggingOperations -ne 'All'){
				$violation += $context.StorageAccountName
			}
			}
			catch
			{
				continue
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz35($violation)
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
return Audit-CISAz35