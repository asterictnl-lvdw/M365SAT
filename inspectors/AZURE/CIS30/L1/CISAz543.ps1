# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That Private Endpoints Are Used Where Possible (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz543($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz543"
		FindingName	     = "CIS Az 5.4.3 - Some Databases are not using Entra ID Client Authentication and Azure RBAC"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "For sensitive data, private endpoints allow granular control of which services can communicate with Cosmos DB and ensure that this network traffic is private. You set this up on a case by case basis for each service you wish to be connected."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlServer -ResourceGroupName <server>.ResourceGroupName -Name <Server>.Name -ssl-enforcement Enabled'
		DefaultValue	 = "By default Cosmos DB does not have private endpoints enabled and its traffic is public to the network."
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Use control plane role-based access control with Azure Cosmos DB for NoSQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cosmos-db/nosql/security/how-to-grant-control-plane-role-based-access?tabs=built-in-definition%2Ccsharp&pivots=azure-interface-cli' })
	}
	return $inspectorobject
}

function Audit-CISAz543
{
	try
	{
		$violation = @()
		$SubscriptionId = Get-AzContext
		$ResourceGroupNames = Get-AzResource | Select-Object ResourceGroupName -Unique
		foreach ($ResourceGroup in $ResourceGroupNames){
			$Databases = Get-AzResource -ResourceType 'Microsoft.DocumentDB/databaseAccounts' -ResourceGroupName $ResourceGroup.ResourceGroupName
			foreach ($Database in $Databases){
				$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/resourceGroups/$($ResourceGroup.ResourceGroupName)/providers/Microsoft.DocumentDB/databaseAccounts/$($Database.Name)?api-version=2024-08-15").content | ConvertFrom-Json)
				if ($Settings.properties.disableLocalAuth -eq $false){
					$violation += $Database.Name
				}
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz543($violation)
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
return Audit-CISAz543