# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'Python version' is the Latest, If Used to Run the Web App
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz98($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz98"
		FindingName	     = "CIS Az 9.8 - 'Python version' is not the Latest, If Used to Run the Web App"
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
		References	     = @(@{ 'Name' = 'Configure an App Service app'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/configure-common?tabs=portal#configure-general-settings' },
		@{ 'Name' = 'PV-6: Rapidly and automatically remediate vulnerabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-7-rapidly-and-automatically-remediate-software-vulnerabilities' },
		@{ 'Name' = 'PV-3: Define and establish secure configurations for compute resources'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-3-define-and-establish-secure-configurations-for-compute-resources' },
		@{ 'Name' = 'Status of Python versions'; 'URL' = 'https://devguide.python.org/versions/' })
	}
	return $inspectorobject
}

function Audit-CISAz98
{
	try
	{
		$LinuxRestMethod = "/providers/Microsoft.Web/availableStacks?osTypeSelected=Linux&api-version=2019-08-01"
		$WindowsRestMethod = "/providers/Microsoft.Web/availableStacks?osTypeSelected=Windows&api-version=2019-08-01"
		#Python Json REST Requests
		
		$Date = Get-Date -Format 'yyyy-MM-dd'
		$PythonVersions = ((Invoke-RestMethod 'https://endoflife.date/api/python.json' -Body $Body)) | where-object {$_.eol -igt $Date}
		$SupportedPythonVersions = $PythonVersions.cycle
		$Violation = @()

		#Python Json REST Requests
		$WinPythonJson = (((Invoke-AzRestMethod -Path $WindowsRestMethod ).Content | ConvertFrom-Json).value.properties | Where-Object {$_.name -eq "python"}).majorversions
		$LinPythonJson = (((Invoke-AzRestMethod -Path $LinuxRestMethod ).Content | ConvertFrom-Json).value.properties | Where-Object {$_.name -eq "python"}).majorversions
		$linpythonversion = $LinPythonJson[0].displayVersion
		$winpythonversion = $WinPythonJson[0].displayVersion
		
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$App = (Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue).SiteConfig
			if (-not [string]::IsNullOrEmpty($App.PythonVersion)) {
				if (-not $SupportedPythonVersions.Contains($App.PythonVersion)){
					$Violation += "$($WebApp.DefaultHostName): runs an EOL Python version: $($App.PythonVersion). The latest version supported is $($linpythonversion) for Linux and $($winpythonversion) for Windows"
				}
			}
			elseif ($null -ne $App.LinuxFxVersion) {
				$Framework = $App.LinuxFxVersion.Split('|')[0]
				if ($Framework.Contains('PYTHON')){
					$Version = $App.LinuxFxVersion.Split('|')[1]
					if (-not $SupportedPythonVersions.Contains($Version)){
						$Violation += "$($WebApp.DefaultHostName): runs an EOL Python version: $($App.LinuxFxVersion.Split('|')[1]). The latest version supported is $($linPythonversion) for Linux."
					}
				}
			}
			elseif ($null -ne $App.WindowsFxVersion){
				$Framework = $App.WindowsFxVersion.Split('|')[0]
				if ($Framework.Contains('PYTHON')){
					$Version = $App.WindowsFxVersion.Split('|')[1]
					if (-not $SupportedPythonVersions.Contains($Version)){
						$Violation += "$($WebApp.DefaultHostName): runs an EOL Python version: $($App.WindowsFxVersion.Split('|')[1]). The latest version supported is $($winpythonversion) for Windows."
					}
				}
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz98($Violation)
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
return Audit-CISAz98