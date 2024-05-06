# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if eDiscovery Case Administrators are Risky
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex012($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex012"
		FindingName	     = "CSTM-Ex012 - Risky eDiscovery Case Administrators"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "9"
		Description	     = "Microsoft Compliance Center eDiscovery provides a method for organizations to search and export content from Microsoft 365 and Office 365. eDiscovery searches are able to access all sources of information, including users' mailboxes to return the requested content. By default, no users are assigned the eDiscovery Administrator role and users may only access cases and searches that they have created."
		Remediation	     = "Review the list of users who are assigned this role, determine if these assignments are appropriate for the tenant and remove any users who should not hold this role."
		PowerShellScript = 'Remove-eDiscoveryCaseAdmin -User example@contoso.com'
		DefaultValue	 = "No eDiscovery Admins"
		ExpectedValue    = "No eDiscovery Admins / Approved Users"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Get started with Core eDiscovery in Microsoft 365'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/get-started-core-ediscovery?view=o365-worldwide" },
			@{ 'Name' = 'More information about the eDiscovery Manager role group'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/get-started-core-ediscovery?view=o365-worldwide#more-information-about-the-ediscovery-manager-role-group" })
	}
	return $inspectorobject
}


Function Inspect-CSTM-Ex012
{
	Try
	{
		try
		{
			$eDiscoveryAdmins = Get-eDiscoveryCaseAdmin
		}
		catch
		{
			$eDiscoveryAdmins = $null
		}
		
		
		if ([string]::IsNullOrEmpty($eDiscoveryAdmins))
		{
			$endobject = Build-CSTM-Ex012($eDiscoveryAdmins.Name)
			return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}
return Inspect-CSTM-Ex012


