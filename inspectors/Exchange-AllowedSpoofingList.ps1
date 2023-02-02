# This is an AllowedSpoofingList Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Spoofingprotection is enabled for the selected tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

$path = @($OutPath)

function Build-AllowedSpoofingList($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0003"
		FindingName	     = "Entities Allowed to Perform Domain Spoofing"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "Domain Spoofing occurs when an external entity sends email using a mail domain owned by another entity. There are legitimate use cases where domain spoofing is allowed. It is recommended to speak with stakeholders and determine if this type of rule is beneficial and if any exceptions are needed. Microsoft configures some Anti-Spoofing settings by default in the Anti-Phishing policies on tenants, this rule would complement default settings."
		Remediation	     = "Review the Tenant Allow/Block List under Spoofing in the Security console."
		PowerShellScript = ''
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Manage the Tenant Allow/Block List in EOP'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/tenant-allow-block-list?view=o365-worldwide' })
	}
	return $inspectorobject
}

function Get-AllowedSpoofingList
{
	Try
	{
		
		$Objects = Get-TenantAllowBlockListSpoofItems | Where-Object { $_.Action -eq "Allow" }
		$sendingInfrastructure = @()
		
		If ($Objects.Count -ne 0)
		{
			ForEach ($Object in $Objects)
			{
				$Object | Export-Csv -Path "$($path)\AllowedSpoofingList.csv" -NoTypeInformation -Append
				$sendingInfrastructure += $Object.SendingInfrastructure
			}
			$finalobject = Build-AllowedSpoofingList($sendingInfrastructure)
			return $finalobject
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

return Get-AllowedSpoofingList


