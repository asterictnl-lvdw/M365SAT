# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft 365
# Purpose: Ensure that only organizationally managed/approved public groups exist
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff121($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff121"
		FindingName	     = "CIS MOff 1.2.1 - Public Microsoft 365 Groups Found!"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "0"
		Description	     = "Ensure that only organizationally managed and approved public groups exist. When a group has a 'public' privacy, users may access data related to this group."
		Remediation	     = "Remove or make specific groups private"
		PowerShellScript = '-'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.Count
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Groups Self-Service Management'; 'URL' = "https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-self-service-management" },
			@{ 'Name' = 'Compare Groups'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/create-groups/compare-groups?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMOff121
{
	Try
	{
		
		$PublicGroups = (Get-MgGroup | where { $_.Visibility -eq "Public" } | select DisplayName, Visibility)
		
		If ($PublicGroups.Count -igt 0)
		{
			$PublicGroups | Format-Table -AutoSize DisplayName, Visibility | Out-File "$path\CISMOff121PublicGroups.txt"
			$endobject = Build-CISMOff121($PublicGroups)
			Return $endobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Audit-CISMOff121


