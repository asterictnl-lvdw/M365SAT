# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if the ATP Policy is correctly configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex003($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex003"
		FindingName	     = "CSTM-Ex003 - ATP Policy Not Optimally Configured"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "By using Office 365 Advanced Threat Protection you can add additional protection to the email filtering service available in Office 365 called Exchange Online Protection (EOP)."
		Remediation	     = "Use the PowerShell command to optimally configure the ATPPolicy for your Office 365 environment"
		PowerShellScript = 'Set-AtpPolicyForO365 -Identity "Default" -EnableATPForSPOTeamsODB $true -AllowClickThrough $false -AllowSafeDocsOpen $false -EnableSafeDocs $true -TrackClicks $true -EnableMailboxIntelligence $true -EnableSafeLinksForO365Clients $true'
		DefaultValue	 = "AllowClickThrough: True; AllowSafeDocsOpen: True;"
		ExpectedValue    = "AllowClickThrough: False; AllowSafeDocsOpen: False; Rest of the options must be true!"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure global settings for Safe Links in Microsoft Defender for Office 365'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-global-settings-for-safe-links?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex003
{
	try
	{
		$ATPViolation = @()
		#Checks if AntiPhish Policies have a optimal configuration
		$ATPPolicies = Get-AtpPolicyForO365 | Select-Object AllowClickThrough, EnableATPForSPOTeamsODB, EnableSafeDocs, AllowSafeDocsOpen
		foreach ($Policy in $ATPPolicies)
		{
			$finalobject += $ATPPolicy.Name
			if ($Policy.AllowClickThrough -eq $false)
			{
				$ATPViolation += "AllowClickThrough: false"
			}
			
			if ($Policy.AllowSafeDocsOpen -eq $false)
			{
				$ATPViolation += "AllowSafeDocsOpen: false"
			}
			
			if ($Policy.EnableSafeDocs -eq $true)
			{
				$ATPViolation += "EnableSafeDocs: true"
			}
			
			if ($Policy.EnableATPForSPOTeamsODB -eq $true)
			{
				$ATPViolation += "EnableATPForSPOTeamsODB: true"
			}
			
		}
		if ([string]::IsNullOrEmpty($ATPViolation) -or $ATPViolation.count -igt 0)
		{
			$endobject = Build-CSTM-Ex003($ATPViolation)
			return $endobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

return Audit-CSTM-Ex003