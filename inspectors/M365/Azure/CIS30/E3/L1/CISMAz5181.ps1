# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Checks if Password Sync is enabled or not
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5181($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5181"
		FindingName	     = "CIS MAz 5.1.8.1 - Password Synchronization Disabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Password hash synchronization helps by reducing the number of passwords your users need to maintain to just one and enables leaked credential detection for your hybrid accounts. Leaked credential protection is leveraged through Azure AD Identity Protection and is a subset of that feature which can help identity if an organization's user account passwords have appeared on the dark web or public spaces. Using other options for your directory synchronization may be less resislient as Microsoft can still process sign-ins to 365 with Hash Sync even if a network connection to your on-premises environment is not available."
		Remediation	     = "Follow Microsoft guidance and best practices to ensure your hybrid configuration meets your business needs and policies."
		PowerShellScript = 'https://stackoverflow.com/questions/62036670/is-there-any-ps-command-to-disable-password-hash-sync'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'What is password hash synchronization with Microsoft Entra ID?'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-phs" },
			@{ 'Name' = 'What are risk detections?'; 'URL' = "https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#user-linked-detections" })
	}
}

Function Audit-CISMAz5181
{
	Try
	{
		
		$OnPremiseSyncEnabledCheck = Get-MgOrganization | Select-Object OnPremisesSyncEnabled
		if ($OnPremiseSyncEnabledCheck.OnPremisesSyncEnabled -ne $true)
		{
			$OnPremiseSyncEnabledCheck | Format-Table -AutoSize | Out-File "$path\CISMAz5181-OnPremiseSyncEnabledCheck.txt"
			$endobject = Build-CISMAz5181("Password Synchronization is disabled!")
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

Return Audit-CISMAz5181


