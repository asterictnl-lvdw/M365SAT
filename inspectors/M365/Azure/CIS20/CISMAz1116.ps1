# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that only organizationally managed/approved public groups exist
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz1116($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz1116"
		FindingName	     = "CIS MAz 1.1.16 - Public Microsoft 365 Groups Found"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "3"
		Description	     = "Ensure that only organizationally managed and approved public groups exist. When a group has a 'Public' privacy, users may access data related to this group. Administrators are notified when a user uses the Azure Portal. Requesting access to the group forces users to send a message to the group owner, but they still have immediately access to the group. The SharePoint URL is usually guessable, and can be found from the Group application of the Access Panel. If group privacy is not controlled, any user may access sensitive information, according to the group they try to access."
		Remediation	     = "Unfortunately we cannot accurately detect if a Privileged Identity Management is active. In order to check this you must have AAD P2 License assigned to your subscription."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/quickstart/resourceId//resourceType/tenant/provider/aadroles'
		DefaultValue	 = "Public when create from the Administration portal; private otherwise."
		ExpectedValue    = "Private where necessary"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "3"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'How To: Give risk feedback in Azure AD Identity Protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-risk-feedback' })
	}
	return $inspectorobject
}

function Audit-CISMAz1116
{
	try
	{
		# Actual Script
		$Groups = @()
		$GroupList = Get-MgGroup | where { $_.Visibility -eq "Public" } | select DisplayName, Visibility
		foreach ($Group in $GroupList)
		{
			$Groups += $Group.DisplayName
		}
		$GroupList | Format-Table -AutoSize | Out-File "$path\CISMAZ1116M365PublicGroups.txt"
		
		# Validation
		if ($Groups.Count -ne 0)
		{
			$finalobject = Build-CISMAz1116($Groups)
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
return Audit-CISMAz1116