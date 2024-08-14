# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure custom script execution is restricted on personal sites
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMSp733($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp733"
		FindingName	     = "CIS MSp 7.3.3 - Custom script execution is not restricted on personal sites"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "0"
		Description	     = "Custom scripts could contain malicious instructions unknown to the user or administrator. When users are allowed to run custom script, the organization can no longer enforce governance, scope the capabilities of inserted code, block specific parts of code, or block all custom code that has been deployed."
		Remediation	     = "Use the link to manually enable the restriction."
		PowerShellScript = 'https://admin.microsoft.com/sharepoint'
		DefaultValue	 = "Prevent users from running custom script on personal sites, Prevent users from running custom script on self-service created sites"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Security considerations of allowing custom script'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/security-considerations-of-allowing-custom-script' },
			@{ 'Name' = 'Allow or prevent custom script'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/allow-or-prevent-custom-script' })
	}
}

function Audit-CISMSp733
{
	try
	{
		$endobject = Build-CISMSp733("Could not verify!")
		return $endobject
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMSp733