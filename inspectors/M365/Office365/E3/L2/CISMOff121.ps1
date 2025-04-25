# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft 365
# Purpose: Ensure that only organizationally managed/approved public groups exist
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff121
{
	param(
		$ReturnedValue,
		$Status,
		$RiskScore,
		$RiskRating
	)

	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		UUID			 = "CISMOff121"
		ID				 = "1.2.1"
		Title		     = "(L2) Ensure that only organizationally managed/approved public groups exist"
		ProductFamily    = "Microsoft Office 365"
		DefaultValue	 = "Public when created from the Administration portal; private otherwise."
		ExpectedValue    = "0 Public Groups"
		ReturnedValue    = "$ReturnedValue Public Groups"
		Status			 = $Status
		RiskScore	     = $RiskScore
		RiskRating	     = $RiskRating
		Description	     = "Ensure that only organizationally managed and approved public groups exist. When a group has a 'public' privacy, users may access data related to this group. Administrators are notified when a user uses the Azure Portal. Requesting access to the group forces users to send a message to the group owner, but they still have immediate access to the group. The SharePoint URL is usually guessable and can be found from the Group application of the Access Panel. If group privacy is not controlled, any user may access sensitive information, according to the group they try to access."
		Impact	     	 = "If the recommendation is applied, group owners could receive more access requests than usual, especially regarding groups originally meant to be public"
		Remediation		 = '-'		
		References	     = @(@{ 'Name' = 'Groups Self-Service Management'; 'URL' = "https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-self-service-management" },
			@{ 'Name' = 'Compare Groups'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/create-groups/compare-groups?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMOff121
{
	Try
	{
		
		$PublicGroups = (Get-MgGroup | Where-Object { $_.Visibility -eq "Public" } | Select-Object DisplayName, Visibility)
		
		If ($PublicGroups.DisplayName.Count -igt 0)
		{
			#$PublicGroups | Format-Table -AutoSize DisplayName, Visibility | Out-File "$path\CISMOff121-PublicGroups.txt"
			$endobject = Build-CISMOff121 -ReturnedValue $PublicGroups.DisplayName.Count -Status "FAIL" -RiskScore "0" -RiskRating "Informational"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMOff121 -ReturnedValue $PublicGroups.DisplayName.Count -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		
	}
	catch
	{
		$endobject = Build-CISMOff121 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
	
}

return Audit-CISMOff121


