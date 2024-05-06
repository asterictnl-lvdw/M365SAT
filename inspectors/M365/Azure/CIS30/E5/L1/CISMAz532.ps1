# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Access reviews' for Guest Users are configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

# Applies for CISMAz533 as well. 
function Build-CISMAz532($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz532"
		FindingName	     = "CIS MAz 5.3.2 - 'Access reviews' for Guest Users are not configured"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Access to groups and applications for guests can change over time. If a guest user's access to a particular folder goes unnoticed, they may unintentionally gain access to sensitive data if a member adds new files or data to the folder or application. Access reviews can help reduce the risks associated with outdated assignments by requiring a member of the organization to conduct the reviews. Furthermore, these reviews can enable a fail-closed mechanism to remove access to the subject if the reviewer does not respond to the review."
		Remediation	     = "This script cannot automatically verify all objects within the AccessReview policy. There is no PowerShell Script available. Please follow the link in PowerShellScript and create the Access Review Policy. Check if the Access Policy exist and if create one if neccesary."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ERM/DashboardBlade/~/Controls/fromNav/Identity'
		DefaultValue	 = "By default access reviews are not configured."
		ExpectedValue    = "A Policy"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Create an access review of groups and applications in Mirosoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/create-access-review' },
			@{ 'Name' = 'What are access reviews?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview' })
	}
	return $inspectorobject
}

function Audit-CISMAz532
{
	try
	{
		# Actual Script
		$AccessReviews = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/identityGovernance/accessReviews/definitions")
		
		# Validation
		if ($AccessReviews.value.count -igt 0)
		{
			$AccessReviews | Format-Table -AutoSize | Out-File "$path\CISMAz532-AccessReviews.txt"
			$finalobject = Build-CISMAz532($AuthorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants)
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
return Audit-CISMAz532