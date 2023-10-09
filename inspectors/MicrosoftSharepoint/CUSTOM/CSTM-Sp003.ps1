# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Sharepoint
# Purpose: Ensure Idle Browser SignOut is correctly configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Sp003($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Sp003"
		FindingName	     = "CSTM-Sp003 - SharePoint Legacy Authentication is Enabled"
		ProductFamily    = "Microsoft SharePoint"
		RiskScore	     = "15"
		Description	     = "SharePoint legacy authentication is enabled. Cyber adversaries frequently attempt credential stuffing and other attacks against legacy authentication protocols because they are subject to less scrutiny and are typically exempt from multi-factor authentication and other modern access requirements. It is recommended to globally disable SharePoint legacy authentication."
		Remediation	     = "Use the PowerShell Script to mitigate the issue and disable Legacy Authentication for SharePoint"
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		PowerShellScript = 'Set-SPOTenant -LegacyAuthProtocolsEnabled $False'
		References	     = @(@{ 'Name' = 'Set-SPOTenant Reference'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' },
			@{ 'Name' = 'How to: Block legacy authentication to Azure AD with conditional access'; 'URL' = 'https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication' },
			@{ 'Name' = 'Legacy Auth and the Risk'; 'URL' = 'https://contosoedu.com/legacy-auth-and-the-risk/' })
	}
}

function Inspect-CSTM-Sp003
{
	Try
	{
		
		If ($(Get-SPOTenant).LegacyAuthProtocolsEnabled)
		{
			$endobject = Build-CSTM-Sp003("Tenant LegacyAuthProtocolsEnabled configuration: $((Get-SPOTenant).LegacyAuthProtocolsEnabled)")
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

return Inspect-CSTM-Sp003


