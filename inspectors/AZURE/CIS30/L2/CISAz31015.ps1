# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Defender External Attack Surface Monitoring (EASM) is enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31015($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31015"
		FindingName	     = "CIS Az 3.1.15 - Notify about alerts with the following severity is not Set to High"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "3"
		Description	     = "This tool can monitor the externally exposed resources of an organization, provide valuable insights, and export these findings in a variety of formats (including CSV) for use in vulnerability management operations and red/purple team exercises."
		Remediation	     = "You can use the PowerShellScript link to go to Microsoft Defender EASM and create a workspace there"
		PowerShellScript = 'https://portal.azure.com/?feature.tokencaching=true&feature.internalgraphapiversion=true#browse/Microsoft.Easm%2Fworkspaces'
		DefaultValue	 = "High"
		ExpectedValue    = "High"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Defender External Attack Surface Management'; 'URL' = 'https://learn.microsoft.com/en-us/azure/external-attack-surface-management/' },
		@{ 'Name' = 'Create a Defender EASM Azure resource'; 'URL' = 'https://learn.microsoft.com/en-us/azure/external-attack-surface-management/deploying-the-defender-easm-azure-resource' },
		@{ 'Name' = 'Uncover adversaries with new Microsoft Defender threat intelligence products'; 'URL' = 'https://www.microsoft.com/en-us/security/blog/2022/08/02/microsoft-announces-new-solutions-for-threat-intelligence-and-attack-surface-management/' })
	}
	return $inspectorobject
}

function Audit-CISAz31015
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id))/providers/Microsoft.Easm/workspaces?api-version=2023-04-01-preview").content | ConvertFrom-Json)
		
		if ([string]::IsNullOrEmpty($Settings.value))
		{
			$finalobject = Build-CISAz31015("No EASM Workspace available")
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
return Audit-CISAz31015