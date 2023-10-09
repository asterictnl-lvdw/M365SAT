# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks if Secure Defaults is enabled or disabled within the tenant
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az006($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az006"
		FindingName	     = "CSTM-Az006 - Azure Security Score is not Maximum Value"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Microsoft Azure encountered that your tenant has not maximum security enabled, thus your secure score could be improved. A lower secure score means that your tenant has recommendations based on security hardening to be able to be configured to enhance security."
		Remediation	     = "Please check the references URL for the actual score and what to fix."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "No Default Value"
		ExpectedValue    = "Maximum Score"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Security Microsoft - SecureScore'; 'URL' = "https://security.microsoft.com/securescore" })
	}
}

function Audit-CSTM-Az006
{
	try
	{
		$command = Get-MgSecuritySecureScore -Top 1 | select CreatedDateTime, CurrentScore, MaxScore
		if ($command.CurrentScore -ne $command.MaxScore)
		{
			$endobject = Build-CSTM-Az006("MaxScore of $($command.CreatedDateTime) is not equal to $($command.MaxScore), The CurrentScore is: " + $command.CurrentScore)
			Return $endobject
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
return Audit-CSTM-Az006