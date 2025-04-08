<# Downloads all Inspectors and creates list #>
function Get-M365SATChecks($Directory, $EnvironmentType, $Modules, $LicenseMode, $LicenseLevel)
{
		if($IsLinux){
			if(Test-Path $Directory){
				rm -rf $Directory
				mkdir $Directory
			}
			else
			{
				mkdir $Directory
			}
			wget 'https://github.com/Karmakstylez/M365SAT-Inspectors/archive/refs/heads/production.zip' -O $Directory/inspectors.zip
			unzip $Directory/inspectors.zip -d $Directory
			mv $Directory/M365SAT-Inspectors-production/inspectors/* $Directory
			rm -rf $Directory/M365SAT-Inspectors-production
			rm $Directory/inspectors.zip
		}
		elseif($IsWindows){
			if (Test-Path $Directory\inspectors){
				Remove-Item -LiteralPath $Directory\inspectors -Force -Recurse
				New-Item -Path $Directory -ItemType Directory
			}
			else
			{
				New-Item -Path $Directory -ItemType Directory
			}
			Invoke-WebRequest 'https://github.com/Karmakstylez/M365SAT-Inspectors/archive/refs/heads/production.zip' -OutFile $Directory\inspectors.zip
			Expand-Archive $Directory\inspectors.zip -DestinationPath $Directory -Force
			Move-Item -Path $Directory\M365SAT-Inspectors-production\inspectors\* -Destination $Directory -Force
			Get-ChildItem -Path $Directory -Recurse -Force | Unblock-File #So no problems will occur when trying to execute inspectors
			Remove-Item -LiteralPath $Directory\M365SAT-Inspectors-production -Force -Recurse
			$tempfiles += "$Directory\inspectors.zip"
		}else{
			if (Test-Path $Directory){
				Remove-Item -LiteralPath $Directory -Force -Recurse
				New-Item -Path $Directory -ItemType Directory
			}
			else
			{
				New-Item -Path $Directory -ItemType Directory
			}
			Invoke-WebRequest 'https://github.com/Karmakstylez/M365SAT-Inspectors/archive/refs/heads/production.zip' -OutFile $Directory\inspectors.zip
			Expand-Archive $Directory\inspectors.zip -DestinationPath $Directory -Force
			Move-Item -Path $Directory\M365SAT-Inspectors-production\inspectors\* -Destination $Directory -Force
			Get-ChildItem -Path $Directory -Recurse -Force | Unblock-File #So no problems will occur when trying to execute inspectors
			Remove-Item -LiteralPath $Directory\M365SAT-Inspectors-production -Force -Recurse
			$tempfiles += "$Directory\inspectors.zip"
		}
		Get-M365SATLocalChecks -Directory $Directory -EnvironmentType $EnvironmentType -Modules $Modules -LicenseMode $LicenseMode -LicenseLevel $LicenseLevel
}

function Get-M365SATLocalChecks($Directory, $EnvironmentType, $Modules, $LicenseMode, $LicenseLevel)
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


		switch ($EnvironmentType) {
			"M365" {  
				#Unblock All Files
				if ($OS -eq "Windows"){
					Get-ChildItem -Path $Directory\$_ -Recurse | Unblock-File
				}
				foreach ($Module in $Modules){
					switch ($LicenseMode) {
						"E3" { 
							switch ($LicenseLevel) {
								"L1" {
									$E3L1Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$E3Folder\$L1Folder\*.ps1 
									foreach ($inspector in $E3L1Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
								"L2" {
									$E3L2Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$E3Folder\$L2Folder\*.ps1 
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
									$E5L1Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$E5Folder\$L1Folder\*.ps1 
									foreach ($inspector in $E5L1Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
								"L2" {
									$E5L2Inspectors = Get-ChildItem $Directory\$M365Folder\$Module\$E5Folder\$L2Folder\*.ps1 
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
				if ($OS -eq "Windows"){
					Get-ChildItem -Path $Directory\$_ -Recurse | Unblock-File
				}
				switch ($LicenseLevel) {
					"L1" {
						$L1Inspectors = Get-ChildItem $Directory\$AZUREFolder\$L1Folder\*.ps1
						foreach ($inspector in $L1Inspectors)
						{
							[string]$fullname = $inspector.FullName
							[string]$name = ($inspector.Name -split ".ps1")[0]
							$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
						}
					}
					"L2" {
						$L2Inspectors = Get-ChildItem $Directory\$AZUREFolder\$L2Folder\*.ps1 
						foreach ($inspector in $L2Inspectors)
						{
							[string]$fullname = $inspector.FullName
							[string]$name = ($inspector.Name -split ".ps1")[0]
							$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
						}
					}
				}
			}
			"CUSTOM" {  
				#Unblock All Files
				if ($OS -eq "Windows"){
					Get-ChildItem -Path $Directory\$_ -Recurse | Unblock-File
				}
				foreach ($Module in $Modules){
					switch ($LicenseMode) {
						"E3" { 
							switch ($LicenseLevel) {
								"L1" {
									$E3L1Inspectors = Get-ChildItem $Directory\$CUSTOMFolder\$Module\$E3Folder\$L1Folder\*.ps1 
									foreach ($inspector in $E3L1Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
								"L2" {
									$E3L2Inspectors = Get-ChildItem $Directory\$CUSTOMFolder\$Module\$E3Folder\$L2Folder\*.ps1 
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
									$E5L1Inspectors = Get-ChildItem $Directory\$CUSTOMFolder\$Module\$E5Folder\$L1Folder\*.ps1 
									foreach ($inspector in $E5L1Inspectors)
									{
										[string]$fullname = $inspector.FullName
										[string]$name = ($inspector.Name -split ".ps1")[0]
										$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
									}
								}
								"L2" {
									$E5L2Inspectors = Get-ChildItem $Directory\$CUSTOMFolder\$Module\$E5Folder\$L2Folder\*.ps1 
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
		}
	$listinspectors = [PSCustomObject]@{
		Inspectors = $listfullinspectors
	}
	
	return $listinspectors
	
}