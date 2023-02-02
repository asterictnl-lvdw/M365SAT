# This is an MSCommonAttachmentTypesFilter Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks common malicious attachments and if they are filtered properly
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSCommonAttachmentTypesFilter($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSO3650007"
		FindingName	     = "Common Malicious Attachment Extensions are Not Filtered"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "9.6"
		Description	     = "O365 includes a list of common malicious file attachment extensions that should be blocked/filtered from O365 emails. The file extensions listed herein are on this list of common malicious file extensions, but no O365 Malware Filter Policy is configured to filter them. Enabling common malicious attachment filtering may decrease the risk of malware spreading within the organization through phishing or lateral phishing. The common malicious attachments defined in O365 at the time this document was authored are= ace, ani, app, docm, exe, jar, reg, scr, vbe, vbs."
		Remediation	     = "This feature is accessible in the Security portal of the O365 Admin Center. Click through to Threat management > Policy > Anti-malware and toggle the Common Attachment Types Filter to 'On'. Additionally, other known dangerous attachment types may be quickly filtered by adding them to this policy's list, although creating a new policy to do this would be a more ideal long-term solution. Before doing this, consider polling key stakeholders in the organization or using available data to determine whether any of these file types are commonly exchanged via email within the organization."
		DefaultValue	 = "ace, ani, app, docm, exe, jar, reg, scr, vbe, vbs"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Unavailable'
		References	     = @(@{ 'Name' = 'Turn on malware protection for your business'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/business-video/anti-malware?view=o365-worldwide' })
	}
}


function Inspect-MSCommonAttachmentTypesFilter
{
	Try
	{
		
		# These file types are from Microsoft's default definition of the common attachment types filter.
		$common_file_types = @("ace", "ani", "app", "docm", "exe", "jar", "reg", "scr", "vbe", "vbs")
		$unfiltered_file_types = @()
		$malware_filters = Get-MalwareFilterPolicy
		
		If ($malware_filters.count -gt 1)
		{
			ForEach ($filter in $malware_filters)
			{
				ForEach ($common_file_type in $common_file_types)
				{
					If (($filter.FileTypes -notcontains $common_file_type) -and ($filter.EnableFileFilter -eq $true))
					{
						$unfiltered_file_types += $common_file_type
						$name = $filter.name
					}
				}
			}
			if ($unfiltered_file_types.count -gt 0)
			{
				$endobject = Build-MSCommonAttachmentTypesFilter("FileTypes not filtered: $($unfiltered_file_types -join ","); Filter name: $name")
				Return $endobject
			}
			Else
			{
				Return $null
			}
		}
		Else
		{
			If ($malware_filters.EnableFileFilter -eq $false)
			{
				$endobject = Build-MSCommonAttachmentTypesFilter("Policy $($malware_filters.Name) file type filtering is disabled.")
				Return $endobject
			}
			Else
			{
				ForEach ($common_file_type in $common_file_types)
				{
					If ($malware_filters.FileTypes -notcontains $common_file_type)
					{
						$unfiltered_file_types += $common_file_type
					}
				}
				$endobject = Build-MSCommonAttachmentTypesFilter($unfiltered_file_types)
				Return $endobject
			}
		}
		
		return $null
		
	}
	Catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
	
}

return Inspect-MSCommonAttachmentTypesFilter


