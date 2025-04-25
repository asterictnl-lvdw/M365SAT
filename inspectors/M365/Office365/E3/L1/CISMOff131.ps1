# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff131
{
	param(
		$ReturnedValue,
		$Status,
		$RiskScore,
		$RiskRating
	)

	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		UUID			 = "CISMOff131"
		ID				 = "1.3.1"
		Title		     = "(L1) Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)'"
		ProductFamily    = "Microsoft Office 365"
		DefaultValue	 = "90"
		ExpectedValue    = "2147483647"
		ReturnedValue    = $ReturnedValue
		Status           = $Status
		RiskScore	     = $RiskScore
		RiskRating	     = $RiskRating
		Description	     = "Organizations such as NIST and Microsoft have updated their password policy recommendations to not arbitrarily require users to change their passwords after a specific amount of time, unless there is evidence that the password is compromised, or the user forgot it. They suggest this even for single factor (Password Only) use cases, with a reasoning that forcing arbitrary password changes on users actually make the passwords less secure. Other recommendations within this Benchmark suggest the use of MFA authentication for at least critical accounts (at minimum), which makes password expiration even less useful as well as password protection for Entra ID."
		Impact		     = "When setting passwords not to expire it is important to have other controls in place to supplement this setting. 1. Ban common password, 2. User education against password reuse, 3. MFA Enforcement."
		Remediation 	 = '$Domains = Get-MgDomain; ForEach($Domain in $Domains){Update-MgDomain -DomainId $Domain.Id -PasswordValidityPeriodInDays 2147483647 -PasswordNotificationWindowInDays 30 }'
		References	     = @(@{ 'Name' = 'NIST Special Publication 800-63B'; 'URL' = 'https://pages.nist.gov/800-63-3/sp800-63b.html' },
		@{ 'Name' = 'CIS Password Policy Guide'; 'URL' = 'https://www.cisecurity.org/insights/white-papers/cis-password-policy-guide' },
		@{ 'Name' = 'Set user password to never expire'; 'URL' = 'https://learn.microsoft.com/en-US/microsoft-365/admin/add-users/set-password-to-never-expire?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Audit-CISMOff131
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$CorrectOptions = @()
		$Domains = Get-MgDomain
		ForEach ($Domain in $Domains)
		{
			$GetSettings = Get-MgDomain -DomainId $Domain.Id
			if ($GetSettings.PasswordValidityPeriodInDays -ne 2147483647 -and $GetSettings.PasswordNotificationWindowInDays -ne 30)
			{
				$AffectedOptions += "Domain: $($GetSettings.Id): PasswordValidityPeriodInDays is $($GetSettings.PasswordValidityPeriodInDays)"
			}
			else
			{
				$CorrectOptions += "Domain: $($GetSettings.Id): PasswordValidityPeriodInDays is $($GetSettings.PasswordValidityPeriodInDays)"
			}
		}
		
		# Validation
		if ($AffectedOptions.Count -igt 0)
		{
			$endobject = Build-CISMOff131 -ReturnedValue $AffectedOptions -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMOff131 -ReturnedValue $CorrectOptions -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
	}
	catch
	{
		$endobject = Build-CISMOff131 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMOff131