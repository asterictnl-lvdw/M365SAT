# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure external sharing is restricted by security group
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp728($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp728"
		FindingName	     = "CIS MSp 7.2.8 - Ensure external sharing is restricted by security group!"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "0"
		Description	     = "Organizations wishing to create tighter security controls for external sharing can set this to enforce role-based access control by using security groups already defined in Microsoft Entra."
		Remediation	     = "Use the link to access the sharepoint settings and change the setting there"
		PowerShellScript = 'https://contoso-admin.sharepoint.com/_layouts/15/online/AdminHome.aspx#/sharing'
		DefaultValue	 = "Unchecked"
		ExpectedValue    = "Checked"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Allow only members in specific security groups to share SharePoint and OneDrive files and folders externally'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/manage-security-groups' })
	}
	return $inspectorobject
}

function Audit-CISMSp728
{
	try
	{
			$finalobject = Build-CISMSp728("Cannot Verify!")
			return $finalobject
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMSp728