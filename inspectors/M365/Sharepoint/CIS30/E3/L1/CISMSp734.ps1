# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure custom script execution is restricted on site collections
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp734($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp734"
		FindingName	     = "CIS MSp 7.3.4 - Custom script execution is not restricted on site collections"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "3"
		Description	     = "Custom scripts could contain malicious instructions unknown to the user or administrator. When users are allowed to run custom script, the organization can no longer enforce governance, scope the capabilities of inserted code, block specific parts of code, or block all custom code that has been deployed."
		Remediation	     = "Use the PowerShell Script to mitigate this issue"
		PowerShellScript = 'Get-SPOSite | ForEach-Object { Set-SPOSite -Identity $_.Name -DenyAddAndCustomizePages $true }'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Allow or Prevent Custom Script'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/allow-or-prevent-custom-script' },
			@{ 'Name' = 'Security Considerations of Allowing Custom Scripts'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/security-considerations-of-allowing-custom-script' })
	}
}

function Audit-CISMSp734
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			$SiteViolation = @()
			$Sites = Get-PnPSite | Select-Object Title, Url, DenyAddAndCustomizePages | Where-Object {$_.DenyAddAndCustomizePages -eq "Disabled"}
			foreach ($Site in $Sites)
			{
				$SiteViolation += $Site.Url
			}
			if ($SiteViolation.Count -igt 0)
			{
				$Sites | Format-Table -AutoSize | Out-File "$path\CISMSp734-SPOSite.txt"
				$endobject = Build-CISMSp734($SiteViolation)
				return $endobject
			}
			return $null
		}
		else
		{
			$SiteViolation = @()
			$Sites = Get-SPOSite | Select-Object Title, Url, DenyAddAndCustomizePages | Where-Object {$_.DenyAddAndCustomizePages -eq "Disabled"}
			foreach ($Site in $Sites)
			{
				$SiteViolation += $Site.Url
			}
			if ($SiteViolation.Count -igt 0)
			{
				$Sites | Format-Table -AutoSize | Out-File "$path\CISMSp734-SPOSite.txt"
				$endobject = Build-CISMSp734($SiteViolation)
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
return Audit-CISMSp734