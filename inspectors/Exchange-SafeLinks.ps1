# This is an ATPSafeLinks Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if ATP SafeLinks is enabled in Microsoft Exchange
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-ATPSafeLinks($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0058"
		FindingName	     = "Microsoft Exchange Safe Links Not Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Safe Links is a feature of O365 that enables real-time detection of malicious links in incoming Exchange emails and other Office 365 applications, such as Microsoft Teams. Safe Links is not enabled in the O365 tenant. This may be because the organization does not have the appropriate license level to use the feature, or because it has been disabled. This lowers the amount of built-in protection O365 offers the organization against phishing and other attacks."
		Remediation	     = "Safe Links can be configured by navigating to the Threat Management portal in the Office 365 Security and Compliance center. The first guide below is a quick introduction to enabling Safe Links while the second is a detailed reference."
		PowerShellScript = '$domains = Get-AcceptedDomain;New-SafeLinksPolicy -Name "Safe Links Policy" -IsEnabled $true -EnableSafeLinksForTeams $true -scanurls $true -DeliverMessageAfterScan $true -DoNotAllowClickThrough $true -AllowClickThrough $false -EnableForInternalSenders $true -DoNotTrackUserClicks $false -EnableSafeLinksForEmail $true -EnableSafeLinksForOffice $true; New-SafeLinksRule -Name "Safe Links Rule" -SafeLinksPolicy "Safe Links Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "IsEnabled: True <br /> AllowClickThrough: True <br /> DoNotAllowClickThrough: False <br /> ScanUrls: True <br /> EnableForInternalSenders: True <br /> EnableSafeLinksForTeams: True"
		ExpectedValue    = "IsEnabled: True <br /> AllowClickThrough: False <br /> DoNotAllowClickThrough: True <br /> ScanUrls: True <br /> EnableForInternalSenders: True <br /> EnableSafeLinksForTeams: True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Microsoft Business Videos: Safe Links'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/business-video/safe-links?view=o365-worldwide" },
			@{ 'Name' = 'Microsoft Safe Links reference'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Inspect-ATPSafeLinks
{
	Try
	{
		
		# This will throw an error if the environment under test does not have an ATP license,
		# but should still work.
		Try
		{
			$flag = $false
			
			$safe_links_policies = Get-SafeLinksPolicy
			
			$disabledPolicy = @()
			
			Foreach ($policy in $safe_links_policies)
			{
				If (($policy.EnableSafeLinksForEmail -eq $false) -and ($policy.EnableSafeLinksForTeams -eq $false) -and ($policy.EnableSafeLinksForOffice -eq $false) -and ((Get-SafeLinksRule -Identity ($policy).Identity).State -eq "Enabled"))
				{
					$flag = $true
					$disabledPolicy += "SafeLinks disabled for policy: $($policy.Identity)"
				}
			}
			
			If ($flag -eq $true)
			{
				$endobject = Build-ATPSafeLinks($disabledPolicy)
				Return $endobject
			}
		}
		Catch [System.Management.Automation.CommandNotFoundException] {
			return $null
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

return Inspect-ATPSafeLinks


