# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp722($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp722"
		FindingName	     = "CIS MSp 7.2.2 - SharePoint and OneDrive integration with Azure AD B2B is not enabled!"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "External users assigned guest accounts will be subject to Azure AD access policies, such as multi-factor authentication. This provides a way to manage guest identities and control access to SharePoint and OneDrive resources. Without this integration, files can be shared without account registration, making it more challenging to audit and manage who has access to the organization's data."
		Remediation	     = "Use the PowerShell Script to enable Modern Authentication for Microsoft Exchange Online."
		PowerShellScript = 'Set-SPOTenant -EnableAzureADB2BIntegration $true'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'SharePoint and OneDrive integration with Microsoft Entra B2B'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/sharepoint-azureb2b-integration#enabling-the-integration' },
		@{ 'Name' = 'B2B collaboration overview'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b' })
	}
	return $inspectorobject
}

function Audit-CISMSp722
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$SharepointSetting = Get-SPOTenant | Format-Table EnableAzureADB2BIntegration
		if ($SharepointSetting.EnableAzureADB2BIntegration -ne $True)
		{
			$AffectedOptions += "EnableAzureADB2BIntegration: False"
		}
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp722-SPOTenant.txt"
			$finalobject = Build-CISMSp722($AffectedOptions)
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
return Audit-CISMSp722