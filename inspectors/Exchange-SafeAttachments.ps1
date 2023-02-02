# This is an ATPSafeAttachments Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if ATP SafeAttachment Filter is enabled and protecting Microsoft Exchange
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-ATPSafeAttachments($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0056"
		FindingName	     = "Safe Attachments Not Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "The Microsoft Office 365 Safe Attachments feature is not enabled. Safe Attachments is a Microsoft feature that uses behavioral analysis and detonation in a virtual environment to add another layer of defense against malware on top of existing Exchange Online anti-malware policies. It is recommended to enable this feature. This finding may also indicate that the O365 license tier does not enable ATP features."
		Remediation	     = "Safe Attachments can be configured by navigating to the Threat Management portal in the Office 365 Security and Compliance center. The first reference below is a detailed guide to configuring ATP Safe Attachments."
		PowerShellScript = '$domains = Get-AcceptedDomain;New-SafeAttachmentPolicy -Name "Safe Attachment Policy" -Enable $true -Redirect $false -RedirectAddress $ITSupportEmail New-SafeAttachmentRule -Name "Safe Attachment Rule" -SafeAttachmentPolicy "Safe Attachment Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Deploy ATP with PowerShell'; 'URL' = "https://call4cloud.nl/2020/07/lock-stock-and-office-365-atp-automation/" })
	}
	return $inspectorobject
}

function Inspect-ATPSafeAttachments
{
	Try
	{
		
		# This will throw an error if the environment under test does not have an ATP license,
		# but should still work.
		Try
		{
			$safe_attachment_policies = Get-SafeAttachmentPolicy
			If ($safe_attachment_policies.Enable -ne $true)
			{
				$endobject = Build-ATPSafeAttachments($safe_attachment_policies.Enable)
				Return $endobject
			}
		}
		Catch
		{
			return $null
		}
		
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

return Inspect-ATPSafeAttachments


