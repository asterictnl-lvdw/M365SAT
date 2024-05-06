# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Checks if Logging and Monitoring is compliant by executing various checks
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz5000($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz5000"
		FindingName	     = "CIS Az 5.x.xx - Azure Monitoring and Logging Incompliancy Detected"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "There are some Azure Monitoring and Logging Settings Incompliant. Please review the values which are reported back into the report"
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = '-'
		DefaultValue	 = "-"
		ExpectedValue    = "-"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = '-'; 'URL' = '-' })
	}
	return $inspectorobject
}

function Audit-CISAz5000
{
	try
	{
		$AffectedSettings = @()
		# Due to Get-AzDiagnosticSetting issues this only works with the Azure CLI: https://aka.ms/installazurecliwindows
		$AzCommand = (Get-Module -Name Az.Monitor -WarningAction SilentlyContinue).ExportedCommands
		if ($AzCommand.Count -ne 0)
		{
			$Settings = Invoke-Expression "az monitor diagnostic-settings subscription list --subscription $((Get-AzSubscription).Id) -WarningAction SilentlyContinue | ConvertFrom-Json | Select * -ExpandProperty value | Select * -ExpandProperty logs | Select category,enabled"
			$Settings2 = Get-AzApplicationInsights -WarningAction SilentlyContinue | Select-Object location, name, appid, provisioningState, tenantid
			$resources = Get-AzResource -WarningAction SilentlyContinue
			foreach ($setting in $Settings)
			{
				if ($setting.Enabled -eq $false)
				{
					$AffectedSettings += $setting.category
				}
			}
			if (-not [string]::IsNullOrEmpty($Settings2))
			{
				$AffectedSettings += "ApplicationInsights Returned Null"
			}
			
			foreach ($resource in $resources)
			{
				$diagnosticSetting = Get-AzDiagnosticSetting -ResourceId $resource.id -ErrorAction "SilentlyContinue" -WarningAction SilentlyContinue;
				if ([string]::IsNullOrEmpty($diagnosticSetting))
				{
					$message = "Diagnostic Settings not configured for resource: " + $resource.Name; Write-Output $message
					$AffectedSettings += $message
				}
				else
				{
				}
			}
			
			if ($AffectedSettings.count -ne 0)
			{
				$finalobject = Build-CISAz5000($Settings.enabled)
				return $finalobject
			}
			else
			{
				return $null
			}
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz5000