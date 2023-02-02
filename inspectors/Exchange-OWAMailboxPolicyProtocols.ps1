# This is an ExchangeMailboxPolicyProtocols Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if end-users can view e-mail in offline mode
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-ExchangeMailboxPolicyProtocols($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0054"
		FindingName	     = "Multiple Weak Protocols in Outlook Web Application Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "Some protocols could lead to information exposure towards public areas. Consider disabling the settings to harden Microsoft Exchange Security."
		Remediation	     = "Use the PowerShell Script to disable AllowOfflineOn for all computers"
		PowerShellScript = 'Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -ActiveSyncIntegrationEnabled $false -AdditionalStorageProvidersAvailable $false -BoxAttachmentsEnabled $false -DisableFacebook $true -DropboxAttachmentsEnabled $false -GoogleDriveAttachmentsEnabled $false -LinkedInEnabled $false -OneDriveAttachmentsEnabled $true -OutlookBetaToggleEnabled $true -ReportJunkEmailEnabled $true -SilverlightEnabled $false'
		DefaultValue	 = "Weak Protocols Are Enabled"
		ExpectedValue    = "Weak Protocols Are Disabled"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Reference - Set-OwaMailboxPolicy'; 'URL' = "https://learn.microsoft.com/en-us/powershell/module/exchange/set-owamailboxpolicy?view=exchange-ps" },
			@{ 'Name' = 'OWA Mailbox Policy Configuration - With PowerShell!'; 'URL' = "https://www.powershellgeek.com/2015/03/15/owa-mailbox-policy-configuration-with-powershell/" })
	}
	return $inspectorobject
}
function Audit-ExchangeMailboxPolicyProtocols
{
	try
	{
		$finalobject = @()
		$owamailboxpolicies = Get-OwaMailboxPolicy | select ActiveSyncIntegrationEnabled, SilverlightEnabled, FacebookEnabled, LinkedInEnabled
		$array = @("ActiveSyncIntegrationEnabled", "SilverlightEnabled", "FacebookEnabled", "LinkedInEnabled")
		foreach ($owamailboxpolicy in $owamailboxpolicies)
		{
			$finalobject += $owamailboxpolicy.Name
			foreach ($object in $array)
			{
				if ($owamailboxpolicy.$object -eq $true)
				{
					$finalobject += "$($object) $($owamailboxpolicy.$object)"
				}
			}
		}
		if ($finalobject -ne 0)
		{
			$endobject = Build-ExchangeMailboxPolicyProtocols($finalobject)
			Return $endobject

		}
		else { return $null }
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
return Audit-ExchangeMailboxPolicyProtocols