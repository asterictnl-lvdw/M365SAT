# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: TempPass Settings Check
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az013($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az013"
		FindingName	     = "CSTM-Az013 - Suspicious Activity Cannot be reported"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "9"
		Description	     = "Microsoft has introduced a new Report Suspicious Activity feature in Azure Active Directory (Azure AD). Suspicious activity reports provide detailed information about unusual sign-in attempts to help organizations detect and respond to potential security threats. According to Microsoft, the new feature enables users to report suspicious activities for unknown authentication requests. Users can report the fraudulent attempt via the Microsoft Authenticator app or their phone call. IT Admins can then review the activity logs to investigate and take necessary action to protect their data and resources."
		Remediation	     = "Enable the Suspicious Activity Reporting Feature via the Entra Portal"
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AuthMethodsSettings/fromNav/Identity'
		DefaultValue	 = "reportSuspiciousActivitySettings:default/systemCredentialPreferences:default"
		ExpectedValue    = "reportSuspiciousActivitySettings:default or enabled /systemCredentialPreferences:default or enabled"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Microsoft Now Lets IT Admins Enable Suspicious Activities Reporting in Azure AD'; 'URL' = "https://petri.com/microsoft-suspicious-activities-reporting-azure-ad/#:~:text=How%20to%20enable%20the%20Report%20suspicious%20activity%20feature%20in%20Azure%20AD&text=Sign%20in%20to%20the%20Azure,the%20Report%20Suspicious%20Activity%20option." })
	}
}



Function Audit-CSTM-Az013
{
	Try
	{
		$reportSuspiciousActivitySettingsList = @()
		$reportSuspiciousActivitySettings = Invoke-MgGraphRequest -Method GET https://graph.microsoft.com/beta/authenticationMethodsPolicy
		if ($reportSuspiciousActivitySettings.reportSuspiciousActivitySettings.state -ne 'enabled' -or $reportSuspiciousActivitySettings.reportSuspiciousActivitySettings.state -ne 'default')
		{
			$reportSuspiciousActivitySettingsList += "reportSuspiciousActivitySettings: disabled"
		}
		if ($reportSuspiciousActivitySettings.systemCredentialPreferences.state -ne 'enabled' -or $reportSuspiciousActivitySettings.systemCredentialPreferences.state -ne 'default')
		{
			$reportSuspiciousActivitySettingsList += "systemCredentialPreferences: disabled"
		}
		
		If ($reportSuspiciousActivitySettingsList.count -igt 0)
		{
			$endobject = Build-CSTM-Az013($reportSuspiciousActivitySettingsList)
			Return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Return Audit-CSTM-Az013




