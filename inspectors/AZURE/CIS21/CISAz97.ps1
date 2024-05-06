# Date: 25-1-2023097
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'PHP version' is the Latest, If Used to Run the Web App
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz97($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz97"
		FindingName	     = "CIS Az 9.7 - 'Java version' is not the Latest, If Used to Run the Web App"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Set-AzWebApp -AssignIdentity $True -ResourceGroupName <resource_Group_Name> -Name <App_Name>'
		DefaultValue	 = "By default, this is per-user's choice"
		ExpectedValue    = "Latest version available online"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Configure an App Service app'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/configure-common?tabs=portal#general-settings' })
	}
	return $inspectorobject
}

function Audit-CISAz97
{
	try
	{
		$LinuxRestMethod = "/providers/Microsoft.Web/availableStacks?osTypeSelected=Linux&api-version=2019-08-01"
		$WindowsRestMethod = "/providers/Microsoft.Web/availableStacks?osTypeSelected=Windows&api-version=2019-08-01"

		#Java Json REST Requests
		$WinJavaJson = (((Invoke-AzRestMethod -Path $WindowsRestMethod ).Content | ConvertFrom-Json).value.properties | Where-Object {$_.name -eq "python"}).majorversions
		$LinJavaJson = (((Invoke-AzRestMethod -Path $LinuxRestMethod ).Content | ConvertFrom-Json).value.properties | Where-Object {$_.name -eq "python"}).majorversions
		$linjavaversion = $LinJavaJson[$LinJavaJson.Length-1].displayVersion
		$winjavaversion = $WinJavaJson[$WinJavaJson.Length-1].displayVersion

		$Violation = @()
		
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$App = (Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue).SiteConfig
			if ($null -ne $App.JavaVersion -and ($App.JavaVersion -ilt $linjavaversion -or $App.JavaVersion -ilt $winjavaversion)){
				$Violation += $WebApp.DefaultHostName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz97($Violation)
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
return Audit-CISAz97