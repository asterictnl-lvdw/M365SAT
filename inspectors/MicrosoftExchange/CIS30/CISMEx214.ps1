# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Safe Attachments policy is enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx214($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx214"
		FindingName	     = "CIS MEx 2.1.4 - Safe Attachments Not Enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "15"
		Description	     = "Enabling Safe Attachments policy helps protect against malware threats in email attachments by analyzing suspicious attachments in a secure, cloud-based environment before they are delivered to the user's inbox. This provides an additional layer of security and can prevent new or unseen types of malware from infiltrating the organization's network."
		Remediation	     = "Run the following PowerShell command:"
		PowerShellScript = '$domains = Get-AcceptedDomain; New-SafeAttachmentPolicy -Name "Safe Attachment Policy" -Enable $true -Redirect $false -RedirectAddress $ITSupportEmail New-SafeAttachmentRule -Name "Safe Attachment Rule" -SafeAttachmentPolicy "Safe Attachment Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Deploy ATP with PowerShell'; 'URL' = "https://call4cloud.nl/2020/07/lock-stock-and-office-365-atp-automation/" })
	}
	return $inspectorobject
}

function Inspect-CISMEx214
{
	$SafeAttachmentsViolation = @()
	Try
	{
		
		# This will throw an error if the environment under test does not have an ATP license,
		# but should still work.
		Try
		{
			try
			{
				$safeattachmentpolicy = Get-SafeAttachmentPolicy
				if ($safeattachmentpolicy.Enable -eq $false)
				{
					$SafeAttachmentsViolation += "Enabled: $($safeattachmentpolicy.Enable)"
				}
			}
			catch
			{
				$SafeAttachmentsViolation += "No SafeAttachmentPolicy Found!"
			}
			
			If ($SafeAttachmentsViolation.count -igt 0)
			{
				$endobject = Build-CISMEx214($SafeAttachmentsViolation)
				Return $endobject
			}
		}
		Catch
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

return Inspect-CISMEx214


