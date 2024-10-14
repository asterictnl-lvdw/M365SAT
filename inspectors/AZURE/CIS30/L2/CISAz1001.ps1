# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1001($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1001"
		FindingName	     = "CIS Az 10.1 - Resource Locks are not set for (some) Mission-Critical Azure Resources"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "As an administrator, it may be necessary to lock a subscription, resource group, or resource to prevent other users in the organization from accidentally deleting or modifying critical resources. The lock level can be set to to CanNotDelete or ReadOnly to achieve this purpose."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Get-AzResourceLock -ResourceName <Resource Name> -ResourceType <ResourceType> -ResourceGroupName <Resource Group Name> -Locktype <CanNotDelete/Read-only>'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Lock your resources to protect your infrastructure'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources?tabs=json' },
		@{ 'Name' = 'Azure enterprise scaffold is now the Microsoft Cloud Adoption Framework for Azure'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/resources/azure-scaffold#azure-resource-locks' },
		@{ 'Name' = 'Understand resource locking in Azure Blueprints'; 'URL' = 'https://learn.microsoft.com/en-us/azure/governance/blueprints/concepts/resource-locking' },
		@{ 'Name' = 'AM-4: Limit access to asset management'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-asset-management#am-4-limit-access-to-asset-management' })
	}
	return $inspectorobject
}

function Audit-CISAz1001
{
	try
	{
		$Violation = @()
		#Resource Group
		$AzResources = Get-AzResource | Select-Object ResourceGroupName -Unique
		foreach ($Resource in $AzResources){
			$ResourceLock = Get-AzResourceLock -ResourceGroupName $Resource.ResourceGroupName -AtScope | Select-Object -Unique
			if ([String]::IsNullOrEmpty($ResourceLock)){
				$Violation += $Resource.ResourceGroupName
			}
		}
		#Resouces Based
		$AzResources = Get-AzResource | Select-Object ResourceGroupName,ResourceId,ResourceName,ResourceType -Unique
		foreach ($Resource in $AzResources){
			$ResourceLock = Get-AzResourceLock -ResourceName $Resource.ResourceName -ResourceGroupName $Resource.ResourceGroupName -ResourceType $Resource.ResourceType  | Select-Object -Unique
			if ([String]::IsNullOrEmpty($ResourceLock)){
				$Violation += $Resource.ResourceGroupName
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz1001($violation)
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
return Audit-CISAz1001