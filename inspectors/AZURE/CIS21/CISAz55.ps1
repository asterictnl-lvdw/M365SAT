# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Azure Monitor Resource Logging is Enabled for All Services that Support it
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz55($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz55"
		FindingName	     = "CIS Az 5.5 - Azure Monitor Resource Logging is not Enabled for All Services that Support it"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Typically, production workloads need to be monitored and should have an SLA with Microsoft, using Basic SKUs for any deployed product will mean that that these capabilities do not exist."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzApplicationInsights'
		DefaultValue	 = "Standard it should be enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Compare support plans'; 'URL' = 'https://azure.microsoft.com/en-us/support/plans' },
		@{ 'Name' = 'Support scope and responsiveness'; 'URL' = 'https://azure.microsoft.com/en-us/support/plans/response/' })
	}
	return $inspectorobject
}

function Audit-CISAz55
{
	try
	{
		$Violation = @()
		# It might happen that AzApplicationInsights returns null as then there is no misconfiguration
		$Resources = Get-AzResource | ? { $_.Sku.Tier -EQ "Basic" -or $_.Sku.Tier -like "Consumption"}
		foreach ($Resource in $Resources){
			if ($Resource.Type -like "Microsoft.Network/publicIPAddresses" -or $Resource.Type -like "Microsoft.Network/loadBalancers" -or $Resource.Type -like "Microsoft.Cache/redis" -or $Resource.Type -like "Microsoft.Network/vpnGateways" -or $Resource.Type -like "Microsoft.Sql/servers/databases"){
					$Violation += $Resource.Name
			}
		}
		$Violation

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz55($violation)
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
return Audit-CISAz55