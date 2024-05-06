# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure modern authentication for SharePoint applications is required
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp729($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp729"
		FindingName	     = "CIS MSp 7.2.9 - Guest access to a site or OneDrive does not expire automatically"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "This setting ensures that guests who no longer need access to the site or link no longer have access after a set period of time. Allowing guest access for an indefinite amount of time could lead to loss of data confidentiality and oversight."
		Remediation	     = "Use the PowerShell Script to enable this setting:"
		PowerShellScript = 'Set-SPOTenant -ExternalUserExpireInDays 30 -ExternalUserExpirationRequired $True'
		DefaultValue	 = "60 and false"
		ExpectedValue    = "30 and true"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage sharing settings for SharePoint and OneDrive in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/turn-external-sharing-on-or-off#change-the-organization-level-external-sharing-setting' },
		@{ 'Name' = 'Managing SharePoint Online Security: A Team Effort'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/community/sharepoint-security-a-team-effort' })
	}
	return $inspectorobject
}

function Audit-CISMSp729
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$SharepointSetting = Get-SPOTenant | Format-Table ExternalUserExpirationRequired, ExternalUserExpireInDays
		if ($SharepointSetting.ExternalUserExpireInDays -igt 30)
		{
			$AffectedOptions += "ExternalUserExpireInDays: $($SharepointSetting.ExternalUserExpireInDays)"
		}
		if ($SharepointSetting.ExternalUserExpirationRequired -ne $True)
		{
			$AffectedOptions += "ExternalUserExpirationRequired: False"
		}
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp729-SPOTenant.txt"
			$finalobject = Build-CISMSp729($AffectedOptions)
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
return Audit-CISMSp729