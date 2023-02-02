# This is an OWAMailboxPolicyOfflineMailEnabled Inspector.

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

function Build-OWAMailboxPolicyOfflineMailEnabled($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0053"
		FindingName	     = "Outlook Web Application Offline Mode Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "One of the oft-overlooked features of web mail, known as OWA, is the offline mode feature. This feature leaves an unencrypted copy of the last 500 emails on your device for easy access while you are not connected."
		Remediation	     = "Use the PowerShell Script to disable AllowOfflineOn for all computers"
		PowerShellScript = 'Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AllowOfflineOn NoComputers'
		DefaultValue	 = "No restrictions"
		ExpectedValue    = "NoComputers are allowed to AllowOfflineOn"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Disable offline access in Outlook on the Web at a global level'; 'URL' = "https://social.technet.microsoft.com/Forums/en-US/d2c2ff3f-232b-496b-a1dc-f2f402ae5c0a/disable-offline-access-in-outlook-on-the-web-at-a-global-level?forum=Exch2016Adm" },
			@{ 'Name' = 'Office 365 - Have You Evaluated These Exchange Online Features?'; 'URL' = "https://blogs.perficient.com/2016/03/07/office-365-have-you-evaluated-these-exchange-online-features/" })
	}
	return $inspectorobject
}

function Audit-OWAMailboxPolicyOfflineMailEnabled
{
	$finalobject = @()
	try
	{
		#OWA Mailbox Policy Check Offline
		$OWAMailboxPolicies = Get-OwaMailboxPolicy | Select Id, AllowOfflineOn
		foreach ($policy in $OWAMailboxPolicies)
		{
			$finalobject += $policy.Id
			if ($policy.AllowOfflineOn -eq "AllComputers")
			{
				$finalobject += "AllowOfflineOn: $($policy.AllowOfflineOn)"
			}
		}
		if ($finalobject.count -ne 0)
		{
			$endobject = Build-OWAMailboxPolicyOfflineMailEnabled($finalobject)
			Return $endobject
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
return Audit-OWAMailboxPolicyOfflineMailEnabled