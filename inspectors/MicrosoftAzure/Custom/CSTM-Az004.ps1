# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks for User Accounts Created via Email Verified Self-Service
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az004($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az004"
		FindingName	     = "CSTM-Az004 - User Accounts Created via Email Verified Self-Service Creation Found"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "4"
		Description	     = "Recently a blog was published about a method of tenant takeover using expired domain registrations. This method relied on a domain registration expiring and the domain remaining associated with the tenant. Monitoring account creation types can help detect and alert on attempts to exploit this attack path. Outlined in both Soteria's blog 'Azure AD Default Configuration Blunders' and the newly published 'LetItGo: A Case Study in Expired Domains and Azure AD' blog is the risk of allowing Microsoft's self-service sign-up for Azure Active Directory. Microsoft initially issued fixes for this attack between December 2021 and January 2022, but has since rolled back those efforts."
		Remediation	     = "Review any accounts returned to ensure they are appropriate for the tenant. Determine if the self-service sign-up configuration is appropriate for business needs and either remediate as outlined, or implement a continuous monitoring solution for accounts created via the self-service method."
		PowerShellScript = '-'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'What is self-service sign-up for Azure Active Directory?'; 'URL' = "https://soteria.io/dnsense-online-brand-protection/" },
			@{ 'Name' = 'Azure AD Default Configuration Blunders'; 'URL' = "https://soteria.io/dnsense-online-brand-protection/" })
	}
}

Function Audit-CSTM-Az004
{
	Try
	{
		
		$emailVerifiedUsers = Get-MgUser -All:$true | Where-Object { $_.CreationType -eq "EmailVerified" }
		
		$results = @()
		
		$emailVerifiedUsers | Select-Object AccountEnabled, DisplayName, ShowInAddressList, UserPrincipalName, OtherMails | Format-Table -AutoSize | Out-File "$path\EmailVerifiedUserCreation.txt"
		
		foreach ($account in $emailVerifiedUsers)
		{
			$results += $account.UserPrincipalName
		}
		if ($results -ne $null)
		{
			$endobject = Build-CSTM-Az004($results)
			Return $endobject
		}
		else
		{
			return $null
		}
		
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Return Audit-CSTM-Az004


