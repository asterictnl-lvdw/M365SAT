# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: IP Addresses Spam checker
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex030($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex030"
		FindingName	     = "CSTM-Ex030 - Multiple Weak Protocols in Outlook Web Application Enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "Some protocols could lead to information exposure towards public areas. Consider disabling the settings to harden Microsoft Exchange Security."
		Remediation	     = "Use the PowerShell Script to disable AllowOfflineOn for all computers"
		PowerShellScript = 'Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -ActiveSyncIntegrationEnabled $false -AdditionalStorageProvidersAvailable $false -BoxAttachmentsEnabled $false -DisableFacebook $true -DropboxAttachmentsEnabled $false -GoogleDriveAttachmentsEnabled $false -LinkedInEnabled $false -OneDriveAttachmentsEnabled $true -OutlookBetaToggleEnabled $true -ReportJunkEmailEnabled $true -SilverlightEnabled $false'
		DefaultValue	 = "Weak Protocols Are Enabled"
		ExpectedValue    = "Weak Protocols Are Disabled"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Reference - Set-OwaMailboxPolicy'; 'URL' = "https://learn.microsoft.com/en-us/powershell/module/exchange/set-owamailboxpolicy?view=exchange-ps" },
			@{ 'Name' = 'OWA Mailbox Policy Configuration - With PowerShell!'; 'URL' = "https://www.powershellgeek.com/2015/03/15/owa-mailbox-policy-configuration-with-powershell/" })
	}
	return $inspectorobject
}
function Audit-CSTM-Ex030
{
	try
	{
		$finalobject = @()
		$owamailboxpolicies = Get-OwaMailboxPolicy | Select-Object ActiveSyncIntegrationEnabled, SilverlightEnabled, FacebookEnabled, LinkedInEnabled
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
			$endobject = Build-CSTM-Ex030($finalobject)
			Return $endobject

		}
		else { return $null }
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Ex030