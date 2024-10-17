# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure Office 365 SharePoint infected files are disallowed for download
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp731($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp731"
		FindingName	     = "CIS MSp 7.3.1 - Office 365 SharePoint infected files are NOT disallowed for download"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams protects your organization from inadvertently sharing malicious files. When an infected file is detected, that file is blocked so that no one can open, copy, move, or share it until further actions are taken by the organization's security team."
		Remediation	     = "Use the PowerShell Script to mitigate this issue"
		PowerShellScript = 'Set-SPOTenant -DisallowInfectedFileDownload $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/turn-on-mdo-for-spo-odb-and-teams?view=o365-worldwide' },
			@{ 'Name' = 'Built-in virus protection in SharePoint Online, OneDrive, and Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/virus-detection-in-spo?view=o365-worldwide' })
	}
}

function Audit-CISMSp731
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$DNAIFSP = Get-PnPTenant | Select-Object DisallowInfectedFileDownload
			if ($DNAIFSP.DisallowInfectedFileDownload -match 'False')
			{
				$DNAIFSP | Format-Table -AutoSize | Out-File "$path\CISMSp732-PnPTenant.txt"
				$endobject = Build-CISMSp731("DisallowInfectedFileDownload: $($DNAIFSP.DisallowInfectedFileDownload)")
				return $endobject
			}
			return $null
		}
		else
		{
			$DNAIFSP = Get-SPOTenant | Select-Object DisallowInfectedFileDownload
			if ($DNAIFSP.DisallowInfectedFileDownload -match 'False')
			{
				$DNAIFSP | Format-Table -AutoSize | Out-File "$path\CISMSp732-SPOTenant.txt"
				$endobject = Build-CISMSp731("DisallowInfectedFileDownload: $($DNAIFSP.DisallowInfectedFileDownload)")
				return $endobject
			}
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMSp731