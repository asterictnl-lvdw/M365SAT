# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure the storage account containing the container with activity logs is encrypted with Customer Managed Key (CMK)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz515($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz515"
		FindingName	     = "CIS Az 5.1.5 - The Network Security Group Flow logs are not captured and sent to Log Analytics"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Network Flow Logs provide valuable insight into the flow of traffic around your network and feed into both Azure Monitor and Azure Sentinel (if in use), permitting the generation of visual flow diagrams to aid with analyzing for lateral movement, etc."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'No PowerShell Script Available'
		DefaultValue	 = "By default Network Security Group logs are not sent to Log Analytics"
		ExpectedValue    = "Unknown"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Tutorial: Log network traffic to and from a virtual machine using the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-tutorial' })
	}
	return $inspectorobject
}

function Audit-CISAz515
{
	try
	{
		$Violation = @()
		# There is no script available at this moment to verify this clause
	

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz515($violation)
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
return Audit-CISAz515