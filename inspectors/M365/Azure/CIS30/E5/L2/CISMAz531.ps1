# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Privileged Identity Management' is used to manage roles
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMAz531($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz531"
		FindingName	     = "CIS MAz 5.3.1 - Verify if Priviledged Identity Management (PIM) is used to manage roles"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Organizations want to minimize the number of people who have access to secure information or resources, because that reduces the chance of a malicious actor getting that access, or an authorized user inadvertently impacting a sensitive resource. However, users still need to carry out privileged operations in Azure AD and Office 365. Organizations can give users just-in-time (JIT) privileged access to roles. There is a need for oversight for what those users are doing with their administrator privileges. PIM helps to mitigate the risk of excessive, unnecessary, or misused access rights."
		Remediation	     = "Unfortunately we cannot accurately detect if a Privileged Identity Management is active. In order to check this you must have AAD P2 License assigned to your subscription."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_Azure_PIMCommon/ResourceMenuBlade/~/quickstart/resourceId//resourceType/tenant/provider/aadroles'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Correctly Configured Policy"
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

function Audit-CISMAz531
{
	try
	{
		# Actual Script
		$Violation = @()
		$Subscriptions = (Get-MgSubscribedSku).ServicePlans | ? { $_.ServicePlanName -Like 'AAD_PREMIUM*' }
		foreach ($Subscription in $Subscriptions)
		{
			if ($Subscription.ServicePlanName -ne "AAD_PREMIUM_P2")
			{
				$Violation += "Privileged Identity Management can't be used, because no P2 License is assigned!"
			}
			else
			{
				$Violation += "Please manually check if Priviledged Identity Management is enabled."
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$Violation | Format-Table -AutoSize | Out-File "$path\CISMAz531-Subscriptions.txt"
			$finalobject = Build-CISMAz531($Violation)
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
return Audit-CISMAz531