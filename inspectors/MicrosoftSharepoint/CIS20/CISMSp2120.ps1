# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp2120($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp2120"
		FindingName	     = "CIS MSp 2.12 - SharePoint and OneDrive integration with Azure AD B2B is disabled"
		ProductFamily    = "Microsoft Sharepoint"
		CVS			     = "9.1"
		Description	     = "External users assigned guest accounts will be subject to Azure AD access policies, such as multi-factor authentication. This provides a way to manage guest identities and control access to SharePoint and OneDrive resources. Without this integration, files can be shared without account registration, making it more challenging to audit and manage who has access to the organization's data."
		Remediation	     = "Use the PowerShell Script to mitigate this issue"
		PowerShellScript = 'Set-SPOTenant -EnableAzureADB2BIntegration $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/turn-on-mdo-for-spo-odb-and-teams?view=o365-worldwide' },
			@{ 'Name' = 'Built-in virus protection in SharePoint Online, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/virus-detection-in-spo?view=o365-worldwide' })
	}
}

function Audit-CISMSp2120
{
	try
	{
		$SPOSetting = Get-SPOTenant | ft EnableAzureADB2BIntegration
		if ($SPOSetting.EnableAzureADB2BIntegration -eq $false)
		{
			$endobject = Build-CISMSp2120("EnableAzureADB2BIntegration: $($SPOSetting.EnableAzureADB2BIntegration)")
			return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMSp2120