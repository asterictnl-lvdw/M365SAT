# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Checks if Sharepoint Guest Users cannot reshare items
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMSp725($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp725"
		FindingName	     = "CIS MSp 7.2.5 - SharePoint Guest Users Resharing Permitted"
		ProductFamily    = "Microsoft SharePoint"
		RiskScore	     = "20"
		Description	     = "Sharing and collaboration are key; however, file, folder, or site collection owners should have the authority over what external users get shared with to prevent unauthorized disclosures of information."
		Remediation	     = "Use the PowerShell script to mitigate this issue."
		PowerShellScript = 'Set-SPOTenant -PreventExternalUsersFromResharing $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "5"
		RiskRating	     = "Critical"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage sharing settings'; 'URL' = 'https://docs.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off' },
			@{ 'Name' = 'External sharing overview'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/external-sharing-overview' })
	}
}

function Audit-CISMSp725
{
	Try
	{
		$SharingCapability = (Get-SPOTenant).SharingCapability
		$PreventExternalUsers = (Get-SPOTenant).PreventExternalUsersFromResharing
		If ($SharingCapability -ne "Disabled")
		{
			If ($PreventExternalUsers -eq $False)
			{
				$endobject = Build-CISMSp725("PreventExternalUsersFromResharing: $($PreventExternalUsers)")
				return $endobject
			}
			Else
			{
				return $null
			}
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Audit-CISMSp725


