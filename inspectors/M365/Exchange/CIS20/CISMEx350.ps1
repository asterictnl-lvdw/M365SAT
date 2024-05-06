# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the DLP Policy if configured is correctly enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx350($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx350"
		FindingName	     = "CIS MEx 3.5 - DLP Policies Not Enabled and Enforced"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "2"
		Description	     = "Enabling the default Teams DLP policy rule in Microsoft 365 helps protect an organization's sensitive information by preventing accidental sharing or leakage of that information in Teams conversations and channels."
		Remediation	     = "Use the PowerShell script to create a new DLPCompliancePolicy or review the policies existence and if they are enabled."
		PowerShellScript = 'New-DlpCompliancePolicy -Name "GlobalPolicy" -SharePointLocation All'
		DefaultValue	 = "Enabled (On)"
		ExpectedValue    = "Enabled"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Learn about data loss prevention'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp?view=o365-worldwide" },
			@{ 'Name' = 'Create, test, and tune a DLP policy'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/create-test-tune-dlp-policy?view=o365-worldwide" })
	}
	return $inspectorobject
}

Function Audit-CISMEx350
{
	Try
	{
		try
		{
			$dlpPolicies = Get-DlpCompliancePolicy | Where-Object { $_.Mode -notlike "Enable" }
			
			$policies = @()
			
			foreach ($policy in $dlpPolicies)
			{
				$policies += "$($policy.Name) state is $($policy.mode)"
			}
			foreach ($policy in $dlpPolicies)
			{
				$Validate = Get-DlpCompliancePolicy -Identity $policy.Name | Select-Object TeamsLocation*
				if ($Validate.count -eq 0 -or $Validate.TeamsLocation -eq 0 -or $Validate.TeamsLocationException -igt 0)
				{
					$dlpPolicies = "Incorrectly Configured DLP Policy"
				}
			}
		}
		catch
		{
			$dlpPolicies = "No DLP Compliance Policy"
		}
		$dlpPolicies.Count
		If ([string]::IsNullOrEmpty($dlpPolicies) -or $dlpPolicies -eq "No DLP Compliance Policy" -or $policies.count -eq 0)
		{
			if ($dlpPolicies -ne "No DLP Compliance Policy")
			{
				$endobject = Build-CISMEx350($policies)
				return $endobject
			}
			else
			{
				$endobject = Build-CISMEx350("No DLP Compliance Policy")
				return $endobject
			}
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}
return Audit-CISMEx350


