# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Checks if a LabelPolicy is existing!
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx320($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx320"
		FindingName	     = "No Label Policy Set! Data Classification not Available!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "8"
		Description	     = "By categorizing and applying policy-based protection, SharePoint Online Data Classification Policies can help reduce the risk of data loss or exposure, and enable more effective incident response if a breach does occur."
		Remediation	     = "Use the PowerShell script to create a New Label Policy"
		PowerShellScript = 'New-LabelPolicy -Name "Example Name" -Labels "Example","Domain"'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Policy"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "4"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Top sensitivity labels applied to content'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/compliance/data-classification-overview?view=o365-worldwide#top-sensitivity-labels-applied-to-content" })
	}
	return $inspectorobject
}

function Audit-CISMEx320
{
	try
	{
		try
		{
			$ExistenceLabelPolicy = Get-LabelPolicy
		}
		catch
		{
			$ExistenceLabelPolicy = "No Label Policy Active"
		}
		
		if ($ExistenceLabelPolicy -eq "No Label Policy Active")
		{
			$endobject = Build-CISMEx320($ExistenceLabelPolicy)
			return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx320