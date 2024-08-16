<# Downloads all Inspectors and creates list #>
function Get-M365SATChecks($Directory, $EnvironmentType, $BenchmarkVersion, $Modules, $LicenseMode, $LicenseLevel)
{
	try{
		if($IsLinux){
			if(Test-Path $Directory){
				rm -rf $Directory
			}
			wget 'https://github.com/asterictnl-lvdw/M365SAT-Inspectors/archive/refs/heads/production.zip' -O $PSScriptRoot
			unzip $PSScriptRoot/inspectors.zip
			mv $PSScriptRoot/M365SAT-Inspectors-production/inspectors $PSScriptRoot/inspectors
			rm -rf $PSScriptRoot/M365SAT-Inspectors-production
			rm $PSScriptRoot/inspectors.zip
		}
		elseif($IsWindows){
			if (Test-Path $Directory/inspectors){
				Remove-Item -LiteralPath $Directory/inspectors -Force -Recurse
			}
			Invoke-WebRequest 'https://github.com/asterictnl-lvdw/M365SAT-Inspectors/archive/refs/heads/production.zip' -OutFile $PSScriptRoot\inspectors.zip
			Expand-Archive $PSScriptRoot\inspectors.zip -DestinationPath $PSScriptRoot -Force
			Move-Item -LiteralPath $PSScriptRoot\M365SAT-Inspectors-production\inspectors -Destination $PSScriptRoot\inspectors -Force
			Get-ChildItem -Path $PSScriptRoot\inspectors -Recurse -Force | Unblock-File #So no problems will occur when trying to execute inspectors
			Remove-Item -LiteralPath $PSScriptRoot\M365SAT-Inspectors-production -Force -Recurse
			$tempfiles += "$PSScriptRoot\inspectors.zip"
		}else{
			if (Test-Path $Directory){
				Remove-Item -LiteralPath $Directory -Force -Recurse
			}
			Invoke-WebRequest 'https://github.com/asterictnl-lvdw/M365SAT-Inspectors/archive/refs/heads/production.zip' -OutFile $PSScriptRoot\inspectors.zip
			Expand-Archive $PSScriptRoot\inspectors.zip -DestinationPath $PSScriptRoot -Force
			Move-Item -LiteralPath $PSScriptRoot\M365SAT-Inspectors-production\inspectors -Destination $PSScriptRoot\inspectors -Force
			Get-ChildItem -Path $PSScriptRoot\inspectors -Recurse -Force | Unblock-File #So no problems will occur when trying to execute inspectors
			Remove-Item -LiteralPath $PSScriptRoot/M365SAT-Inspectors-production -Force -Recurse
			$tempfiles += "$PSScriptRoot\inspectors.zip"
		}
		Get-M365SATLocalChecks($Directory, $EnvironmentType, $BenchmarkVersion, $Modules, $LicenseMode, $LicenseLevel)
	}catch{
		#always run the Windows part
		Invoke-WebRequest 'https://github.com/asterictnl-lvdw/M365SAT-Inspectors/archive/refs/heads/production.zip' -OutFile $Directory\inspectors.zip
		Expand-Archive $Directory\inspectors.zip

		Get-ChildItem -Path $Directory -Recurse -Force | Unblock-File #So no problems will occur when trying to execute inspectors
		$tempfiles += "$Directory\inspectors.zip"
		$Directory, $EnvironmentType, $BenchmarkVersion, $Modules, $LicenseMode, $LicenseLevel
	}

}

function Get-M365SATLocalChecks($Directory, $EnvironmentType, $BenchmarkVersion, $Modules, $LicenseMode, $LicenseLevel)
{
	# Initializations
	[Array]$listfullinspectors = @()
	[Array]$listinspectorsfullname = @()
	[Array]$listinspectorsname = @()
	[string]$M365Folder = "M365"
	[string]$AZUREFolder = "AZURE"
	[string]$CUSTOMFolder = "CUSTOM"
	[string]$E3Folder = "E3"
	[string]$E5Folder = "E5"
	[string]$L1Folder = "L1"
	[string]$L2Folder = "L2"

	# Validations
		if ($Modules.Contains("All"))
		{
			[Array]$Modules = @("Azure", "Exchange", "Office365", "Sharepoint", "Teams")
		}
		if ($EnvironmentType.Contains("All")){
			[Array]$EnvironmentType = @("M365","AZURE","CUSTOM")
		}
		if ($LicenseMode.Contains("All")){
			[Array]$LicenseMode = @("E3","E5")
		}
		if ($LicenseLevel.Contains("All")){
			[Array]$LicenseLevel = @("L1","L2")
		}

	# Switch statements
		switch ($BenchmarkVersion) {
			2 {	
				[string]$AzureVersion = "CIS20"
				[string]$M365Version =  "CIS20"
			}
			3 {	
				[string]$AzureVersion = "CIS21"
				[string]$M365Version = "CIS30"
			}
			"Latest"{
				[string]$AzureVersion = "CIS21"
				[string]$M365Version = "CIS31"
			}
		}


		switch ($EnvironmentType) {
			"M365" {  
				#Unblock All Files
				Get-ChildItem -Path $Directory\$_ -Recurse | Unblock-File
				foreach ($Module in $Modules){
					switch ($LicenseMode) {
						"E3" { 
							switch ($LicenseLevel) {
								"L1" {
									$E3L1Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$M365Version\$E3Folder\$L1Folder\*.ps1 
									foreach ($inspector in $E3L1Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
								"L2" {
									$E3L2Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$M365Version\$E3Folder\$L2Folder\*.ps1 
									foreach ($inspector in $E3L2Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
							}
							
						 }
						"E5" {
							switch ($LicenseLevel) {
								"L1" {  
									$E5L1Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$M365Version\$E5Folder\$L1Folder\*.ps1 
									foreach ($inspector in $E5L1Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
								"L2" {
									$E5L2Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$M365Version\$E5Folder\$L2Folder\*.ps1 
									foreach ($inspector in $E5L2Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
							}
						}
					}
					
				}
			}
			"AZURE" {
				#Unblock All Files
				Get-ChildItem -Path $Directory\$_ -Recurse | Unblock-File
				$AzureInspectors = Get-ChildItem $Directory\$AZUREFolder\$AzureVersion\*.ps1
				foreach ($inspector in $AzureInspectors)
				{
					[string]$fullname = $inspector.FullName
					[string]$name = ($inspector.Name -split ".ps1")[0]
					$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
				}
			}
			"CUSTOM"{
				#Unblock All Files
				Get-ChildItem -Path $Directory\$_ -Recurse | Unblock-File
				foreach ($Module in $Modules){
				$CustomInspectors = Get-ChildItem $Directory\$CUSTOMFolder\$Module\*.ps1
					foreach ($inspector in $CustomInspectors)
					{
						[string]$fullname = $inspector.FullName
						[string]$name = ($inspector.Name -split ".ps1")[0]
						$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
					}
				}
			}
		}
	$listinspectors = [PSCustomObject]@{
		Inspectors = $listfullinspectors
	}
	
	return $listinspectors
	
}