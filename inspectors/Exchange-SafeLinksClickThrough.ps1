# This is an SafeLinksClickThrough Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if ATP SafeLinks AllowClickThrough is Disabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-SafeLinksClickThrough($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0060"
		FindingName	     = "Microsoft Exchange Safe Links Click-Through is Allowed"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Advanced Threat Protection Safe Links (ATP Safe Links) is an Office 365 feature that enables the detection of suspicious links used in attacks delivered via Exchange Email and Teams, such as phishing attacks. ATP Safe Links is configured to allow users to click through a link flagged as unsafe if they choose. It is recommended to disable this ability, as users will often click through to potentially unsafe links if they are given the choice, partially negating the benefit of Safe Links."
		Remediation	     = "Use the PowerShell to create a new SafeLinksPolicy to disable and enable all recommended settings!"
		PowerShellScript = '$domains = Get-AcceptedDomain;New-SafeLinksPolicy -Name "Safe Links Policy" -IsEnabled $true -EnableSafeLinksForTeams $true -scanurls $true -DeliverMessageAfterScan $true -DoNotAllowClickThrough $true -AllowClickThrough $false -EnableForInternalSenders $true -DoNotTrackUserClicks $false -EnableSafeLinksForEmail $true -EnableSafeLinksForOffice $true; New-SafeLinksRule -Name "Safe Links Rule" -SafeLinksPolicy "Safe Links Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Set up Safe Links policies in Microsoft Defender for Office 365'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-safe-links-policies?view=o365-worldwide" },
			@{ 'Name' = 'Microsoft Safe Links reference'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links?view=o365-worldwide" })
	}
	return $inspectorobject
}


function Inspect-SafeLinksClickThrough
{
	Try
	{
		
		Try
		{
			$click_through_policies = Get-SafeLinksPolicy
			$flag = $false
			
			If ($click_through_policies.AllowClickThrough -eq $false)
			{
				return $null
			}
			Else
			{
				$flag = $true
			}
		}
		Catch [System.Management.Automation.CommandNotFoundException] {
			return $null
		}
		
		If ($flag -eq $true)
		{
			$endobject = Build-SafeLinksClickThrough("$($click_through_policies.Name): $($click_through_policies.AllowClickThrough)")
			Return $endobject
		}
		return $null
		
	}
	Catch
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

return Inspect-SafeLinksClickThrough


