# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Checks common malicious attachments and if they are filtered properly
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx410($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx410"
		FindingName	     = "CIS MEx 4.1 - Common Attachment Types Filter is disabled!"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "9.6"
		Description	     = "The Common Attachment Types Filter lets a user block known and custom malicious file types from being attached to emails."
		Remediation	     = "Run the following Exchange Online PowerShell command"
		PowerShellScript = 'Set-MalwareFilterPolicy -Identity Default -EnableFileFilter $true'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Turn on malware protection for your business'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/business-video/anti-malware?view=o365-worldwide' })
	}
}


function Inspect-CISMEx410
{
	Try
	{
		
		# These file types are from Microsoft's default definition of the common attachment types filter.
		$malwarefilterpolicy = Get-MalwareFilterPolicy
		
		if ($malwarefilterpolicy.EnableFileFilter -eq $False)
		{
			$finalobject = Build-CISMEx410($malwarefilterpolicy.EnableFileFilter)
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

return Inspect-CISMEx410


