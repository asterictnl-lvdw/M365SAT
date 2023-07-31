# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks if a Directory Sync Service Account is found
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az000($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az000"
		FindingName	     = "CSTM-Az000 - Directory Synchronization Service Account Found"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "0.0"
		Description	     = "Directory synchronization allows you to manage identities in your Active Directory Domain Services (AD DS) and all updates to user accounts, groups, and contacts are synchronized to the Azure Active Directory (Azure AD) tenant of your Microsoft 365 subscription."
		Remediation	     = "Validate the Configuration of the Service Account to determine if default installation procedure is used. If so, please use Microsoft's guidace to apply best practices."
		PowerShellScript = ''
		DefaultValue	 = "-"
		ExpectedValue    = "-"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'ADSync Service accounts'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/concept-adsync-service-account" },
			@{ 'Name' = 'Service accounts'; 'URL' = "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts" },
			@{ 'Name' = 'Virtual accounts'; 'URL' = "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts#bkmk-virtualserviceaccounts" })
	}
}



Function Audit-CSTM-Az000
{
	Try
	{
		
		$permissions = Get-MgOrganization
		
		If ($permissions.OnPremisesSyncEnabled -eq $true)
		{
			$directoryRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Synchronization Accounts" }
			$roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $directoryRole.Id
			$serviceAcct = Get-MgUser -UserId ($roleMembers).Id
			$endobject = Build-CSTM-Az000($serviceAcct.DisplayName)
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

Return Audit-CSTM-Az000




