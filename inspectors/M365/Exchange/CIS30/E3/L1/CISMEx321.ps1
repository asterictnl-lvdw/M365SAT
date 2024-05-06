# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure DLP policies are enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx321($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx321"
		FindingName	     = "CIS MEx 3.2.1 - DLP Policy is not enabled!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "Enabling DLP policies alerts users and administrators that specific types of data should not be exposed, helping to protect the data from accidental exposure."
		Remediation	     = "Use the PowerShell script to configure a New-Dlp Compliance Policy"
		PowerShellScript = 'New-DlpPolicy -Name "Contoso PII"" -Template {templatehere}'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Policy"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Learn about data loss prevention'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMEx321
{
	try
	{
		try
		{
			$dlppolicy = Get-DlpPolicy
			if ([string]::IsNullOrEmpty($dlppolicy))
			{
				$dlppolicy | Format-Table -AutoSize | Out-File "$path\CISMEx321-DLPPolicySettings.txt"
				$endobject = Build-CISMEx321("No DLP Policy Active")
				return $endobject
			}
			else
			{
				return $null
			}
		}
		catch
		{
			$endobject = Build-CISMEx321("No DLP Policy Active")
			return $endobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx321