# This is an ATPPolicyForO365OptimalConfiguration Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the ATP Policy is optimally configured
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-ATPPolicyForO365OptimalConfiguration($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0006"
		FindingName	     = "ATP Policy Not Optimally Configured"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "By using Office 365 Advanced Threat Protection you can add additional protection to the email filtering service available in Office 365 called Exchange Online Protection (EOP)."
		Remediation	     = "Use the PowerShell command to optimally configure the ATPPolicy for your Office 365 environment"
		PowerShellScript = 'Set-AtpPolicyForO365 -Identity "Default" -EnableATPForSPOTeamsODB $true -AllowClickThrough $false -AllowSafeDocsOpen $false -EnableSafeDocs $true -TrackClicks $true -EnableMailboxIntelligence $true -EnableSafeLinksForO365Clients $true'
		DefaultValue	 = "AllowClickThrough: True; AllowSafeDocsOpen: True;"
		ExpectedValue    = "AllowClickThrough: False; AllowSafeDocsOpen: False; Rest of the options must be true!"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Configure global settings for Safe Links in Microsoft Defender for Office 365'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/configure-global-settings-for-safe-links?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Audit-ATPPolicyForO365OptimalConfiguration
{
	try
	{
		$finalobject = @()
		#Checks if AntiPhish Policies have a optimal configuration
		$ATPPolicies = Get-AtpPolicyForO365 | select TrackClicks, AllowClickThrough, EnableATPForSPOTeamsODB, EnableSafeDocs, EnableSafeLinksForO365Clients, AllowSafeDocsOpen
		foreach ($ATPPolicy in $ATPPolicies)
		{
			$finalobject += $ATPPolicy.Name
			#Array for values that are false
			$array = @("AllowClickThrough", "AllowSafeDocsOpen")
			#Array for values that are true
			$array2 = @("EnableSafeDocs", "TrackClicks", "EnableATPForSPOTeamsODB", "EnableMailboxIntelligence", "EnableSafeLinksForO365Clients")
			foreach ($object in $array)
			{
				if ($ATPPolicy.$object -eq $true)
				{
					$object = "$($object): $($ATPPolicy.$object)"
					$finalobject += $object
				}
			}
			foreach ($object in $array2)
			{
				if ($ATPPolicy.$object -eq $false)
				{
					$object = "$($object): $($ATPPolicy.$object)"
					$finalobject += $object
				}
			}
		}
		if ($finalobject.Count -ne 0)
		{
			$endobject = Build-ATPPolicyForO365OptimalConfiguration($finalobject)
			return $endobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}

return Audit-ATPPolicyForO365OptimalConfiguration