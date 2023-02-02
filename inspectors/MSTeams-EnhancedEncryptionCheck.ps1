# This is an MSTeamsEnhancedEncryption Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks the MSTeams Enhanced Encryption Technique End-To-End Encryption
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSTeamsEnhancedEncryption($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMST0005"
		FindingName	     = "Microsoft Teams Enhanced Encryption Not Enabled!"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "6.3"
		Description	     = "Enhanced Encryption enabled more protection on Microsoft Teams. Calling and Meeting end-to-end encryption ensures conversations stay encrypted and cannot be decoded unless users have access to."
		Remediation	     = "Enable End-To-End Encryption. Refer to the references on how to set-up end-to-end encryption in Teams"
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		PowerShellScript = 'Set-CsTeamsEnhancedEncryptionPolicy -Identity Global -CallingEndtoEndEncryptionEnabledType DisabledUserOverride'
		References	     = @(@{ 'Name' = 'Use end-to-end encryption for one-to-one Microsoft Teams calls'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/teams-end-to-end-encryption' })
	}
}


function Audit-MSTeamsEnhancedEncryption
{
	try
	{
		$MSTeamsEnhancedEncryption = @()
		$MSTeamsEnhancedEncryptionCMD = Get-CsTeamsEnhancedEncryptionPolicy -Identity Global
		if ($MSTeamsEnhancedEncryptionCMD.CallingEndtoEndEncryptionEnabledType -contains 'Disabled')
		{
			$MSTeamsEnhancedEncryption += "CallingEndtoEndEncryptionEnabledType: $($MSTeamsEnhancedEncryptionCMD.CallingEndtoEndEncryptionEnabledType)"
		}
		if ($MSTeamsEnhancedEncryptionCMD.MeetingEndToEndEncryption -contains 'Disabled')
		{
			$MSTeamsEnhancedEncryption += "MeetingEndToEndEncryption: $($MSTeamsEnhancedEncryptionCMD.MeetingEndToEndEncryption)"
		}
		if ($MSTeamsEnhancedEncryption.Count -gt 0)
		{
			$endobject = Build-MSTeamsEnhancedEncryption($MSTeamsEnhancedEncryption)
			Return $endobject
		}
		return $null
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
return Audit-MSTeamsEnhancedEncryption