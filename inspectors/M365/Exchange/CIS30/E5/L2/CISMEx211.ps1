# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Safe Links for Office Applications is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx211($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx211"
		FindingName	     = "CIS MEx 2.1.1 - Safe Links for Office Applications is not Enabled!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "Enabling Safe Links policy for Office applications allows URL's that exist inside of Office documents and email applications opened by Office, Office Online and Office mobile to be processed against Defender for Office time-of-click verification and rewritten if required. Safe Links for Office applications extends phishing protection to documents and emails that contain hyperlinks, even after they have been delivered to a user."
		Remediation	     = "Use the PowerShell Script to create and apply the policy within your organization."
		PowerShellScript = '$params = @{ Name = "CIS SafeLinks Policy" EnableSafeLinksForEmail = $true EnableSafeLinksForTeams = $true EnableSafeLinksForOffice = $true TrackClicks = $true AllowClickThrough = $false ScanUrls = $true EnableForInternalSenders = $true DeliverMessageAfterScan = $true DisableUrlRewrite = $false }; New-SafeLinksPolicy @params ; New-SafeLinksRule -Name "CIS SafeLinks" -SafeLinksPolicy "CIS SafeLinks Policy" -RecipientDomainIs (Get-AcceptedDomain).Name -Priority 0 '
		DefaultValue	 = "Undefined"
		ExpectedValue    = "EnableSafeLinksForEmail: True EnableSafeLinksForTeams: True EnableSafeLinksForOffice: True TrackClicks: True AllowClickThrough: False ScanUrls: True EnableForInternalSenders: True DeliverMessageAfterScan: True DisableUrlRewrite: False"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "4"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'SafeLinks Policy Configuration'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/safe-links-policies-configure?view=o365-worldwide' },
		@{ 'Name' = 'Preset Security Policies'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide' })
}
	return $inspectorobject
}

function Audit-CISMEx211
{
	$AffectedSettings = @()
	try
	{
		# Actual Script
		try
		{
			$Policies = Get-SafeLinksPolicy | Format-Table Name
			foreach($Policy in $Policies)
			{
				$Settings = Get-SafeLinksPolicy -Identity $Policy.Name
				if ($Settings.EnableSafeLinksForEmail -eq $false -or $Settings.EnableSafeLinksForTeams -eq $false -or $Settings.EnableSafeLinksForOffice -eq $false -or $Settings.TrackClicks -eq $false -or $Settings.AllowClickThrough -eq $true -or $Settings.ScanUrls -eq $false -or $Settings.EnableForInternalSenders -eq $false -or $Settings.DeliverMessageAfterScan -eq $false -or $Settings.DisableUrlRewrite -eq $true)
				{
					$AffectedSettings += $Policy.Name
				}
				if ($Settings.EnableSafeLinksForEmail -eq $false)
				{
					$AffectedSettings += "EnableSafeLinksForEmail: $($Settings.EnableSafeLinksForEmail)"
				}
				if ($Settings.EnableSafeLinksForTeams -eq $false)
				{
					$AffectedSettings += "EnableSafeLinksForTeams: $($Settings.EnableSafeLinksForTeams)"
				}
				if ($Settings.EnableSafeLinksForOffice -eq $false)
				{
					$AffectedSettings += "EnableSafeLinksForOffice: $($Settings.EnableSafeLinksForOffice)"
				}
				if ($Settings.TrackClicks -eq $false)
				{
					$AffectedSettings += "TrackClicks: $($Settings.TrackClicks)"
				}
				if ($Settings.AllowClickThrough -eq $true)
				{
					$AffectedSettings += "AllowClickThrough: $($Settings.AllowClickThrough)"
				}
				if ($Settings.ScanUrls -eq $false)
				{
					$AffectedSettings += "ScanUrls: $($Settings.ScanUrls)"
				}
				if ($Settings.EnableForInternalSenders -eq $false)
				{
					$AffectedSettings += "EnableForInternalSenders: $($Settings.EnableForInternalSenders)"
				}
				if ($Settings.DeliverMessageAfterScan -eq $false)
				{
					$AffectedSettings += "DeliverMessageAfterScan: $($Settings.DeliverMessageAfterScan)"
				}
				if ($Settings.DisableUrlRewrite -eq $true)
				{
					$AffectedSettings += "DisableUrlRewrite: $($Settings.DisableUrlRewrite)"
				}
			}
		}
		catch
		{
			$AffectedSettings += "Subscription is not Active. Thus SafeLinks is not working"
		}
		
		# Validation
		if ($AffectedSettings.Count -igt 0)
		{
			$AffectedSettings | Format-Table -AutoSize | Out-File "$path\CISMEx211-SafeLinksPolicySettings.txt"
			$finalobject = Build-CISMEx211($AffectedSettings)
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
return Audit-CISMEx211