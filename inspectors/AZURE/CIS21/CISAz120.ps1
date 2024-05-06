# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Users can create Microsoft 365 groups in Azure portals, API or PowerShell' is set to 'No'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz120($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1200"
		FindingName	     = "CIS Az 1.20 - Users can create Microsoft 365 groups in Azure portals, API or PowerShell"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Restricting Microsoft 365 group creation to administrators only ensures that creation of Microsoft 365 groups is controlled by the administrator. Appropriate groups should be created and managed by the administrator and group creation rights should not be delegated to any other user."
		Remediation	     = "Use the Powershell Script to modify the setting back to False. Else goto the Azure Portal: https://portal.azure.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General to fix this issue. Note: You will need to get the DirectorySettingID to implement the setting correctly!"
		PowerShellScript = '$params = @{ Values = @(@{ Name = "EnableGroupCreation"; Value = "False" }) }; Update-MgDirectorySetting -DirectorySettingId $directorySettingId -BodyParameter $params'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'So, You Can Disable Office 365 Groups After All'; 'URL' = 'https://whitepages.bifocal.show/2017/01/disable-office-365-groups-2/' },
			@{ 'Name' = 'Manage who can create Microsoft 365 Groups'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/solutions/manage-creation-of-groups?view=o365-worldwide' },
			@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
			@{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategyment'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
			@{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' })
	}
	return $inspectorobject
}

function Audit-CISAz120
{
	try
	{
		$AffectedObject = @()
		# Actual Script
		$BetaSettings = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/settings")
		$hash = $BetaSettings.value.values
		$BetaSettingsObject = [PSCustomObject]@{ } #Create Custom Object
		# Convert HashTable names to name and assign value to it so we can correctly make the CustomObject
		foreach ($h in $hash.GetEnumerator())
		{
			$BetaSettingsObject | Add-Member -MemberType NoteProperty -Name $h.Name -Value $h.Value
		}
		
		# Validation
		if ($BetaSettingsObject.EnableGroupCreation -eq $true)
		{
			$finalobject = Build-CISAz1200("EnableGroupCreation: $($BetaSettingsObject.EnableGroupCreation)")
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz120