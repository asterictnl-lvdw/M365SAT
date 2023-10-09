# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Sharepoint
# Purpose: Ensure Idle Browser SignOut is correctly configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Sp001($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Sp001"
		FindingName	     = "CSTM-Sp001 - Sharepoint has no Idle Browser SignOut Configuration Configured"
		ProductFamily    = "Microsoft SharePoint"
		RiskScore	     = "9"
		Description	     = "Idle session timeout in SharePoint Online is a security mechanism that warns and sign-outs the user after a period of inactivity. By default, idle session timeout settings are disabled in SharePoint Online. Not enabling leaves the user at risk for step-by attacks."
		Remediation	     = "Execute the following command to enable Idle Session Timeout= <b>  </b>"
		DefaultValue	 = 'Enabled= False, WarnAfter= 0, SignOutAfter= 0'
		ExpectedValue    = 'Enabled= True, WarnAfter= 30, SignOutAfter 60'
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		PowerShellScript = 'Set-SPOBrowserIdleSignOut -Enabled $true -WarnAfter (New-TimeSpan -Minutes 30) -SignOutAfter (New-TimeSpan -Minutes 60)'
		References	     = @(@{ 'Name' = 'Enforcing idle session timeout restrictions in SharePoint Online'; 'URL' = 'https://www.michev.info/Blog/Post/1857/enforcing-idle-session-timeout-restrictions-in-sharepoint-online' })
	}
}


function Audit-CSTM-Sp001
{
	try
	{
		$command = Get-SPOBrowserIdleSignOut | Select-Object Enabled
		if ($command.Enabled -eq $false)
		{
			$endobject = Build-CSTM-Sp001("SPOBrowserIdleSignOut: $($command.Enabled)")
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
return Audit-CSTM-Sp001