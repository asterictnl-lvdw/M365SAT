<# Downloads all Inspectors and creates list #>
function Get-M365SATChecks($Directory, $Modules, $CustomModules)
{
	<# This is only for the Online Version. And is in beta, this script will be improved upon future releases #>
<# Downloads the Inspectors from Github and extracts them to the powershellmodule location #>
	Invoke-WebRequest 'https://github.com/asterictnl-lvdw/M365SAT-inspectors/archive/refs/heads/main.zip' -OutFile $Directory\inspectors.zip
	# Name of the Directory
	Expand-Archive $Directory\inspectors.zip
	Rename-Item $Directory\365inspect-main $Directory\inspectors
	Get-ChildItem -Path $Directory\inspectors -Recurse | Unblock-File #So no problems will occur when trying to execute inspectors
	$tempfiles += "$Directory\inspectors.zip"
<# Creates List of All Inspectors #>
	
	if ($Modules.Contains("All"))
	{
		$Modules = @("MicrosoftAzure", "MicrosoftExchange", "MicrosoftOffice365", "MicrosoftSharepoint", "MicrosoftTeams")
	}
	
	$Folder = "CIS20"
	$listfullinspectors = @()

	$listinspectorsfullname = @()
	$listinspectorsname = @()
	
	if ($CustomModules -eq $true)
	{
		foreach ($Module in $Modules)
		{
			Get-ChildItem -Path $Directory\inspectors\$Module\$Folder -Recurse | Unblock-File
			Get-ChildItem -Path $Directory\inspectors\$Module\CUSTOM -Recurse | Unblock-File
			#AllInspectors
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			foreach ($inspector in $AllInspectors)
			{
				$fullname = $inspector.FullName
				$name = ($inspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
			}

			$AllCustomInspectors = Get-ChildItem $Directory\$Module\CUSTOM\*.ps1
			foreach ($custominspectors in $AllCustomInspectors)
			{
				$customfullname = $custominspectors.FullName
				$customname = ($custominspectors.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $customfullname; 'Name' = $customname })
			}
		}
	}
	else
	{
		foreach ($Module in $Modules)
		{
			Get-ChildItem -Path $Directory\$Module\$Folder -Recurse | Unblock-File
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			foreach ($inspector in $AllInspectors)
			{
				$fullname = $inspector.FullName
				$name = ($inspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
			}
		}
	}
	$listinspectors = [PSCustomObject]@{
		Inspectors = $listfullinspectors
	}
	return $listinspectors
}

function Get-M365SATLocalChecks($Directory, $Modules, $CustomModules)
{
	if ($Modules.Contains("All"))
		{
			$Modules = @("MicrosoftAzure", "MicrosoftExchange", "MicrosoftOffice365", "MicrosoftSharepoint", "MicrosoftTeams")
		}
	
	$Folder = "CIS20"
	$listinspectorsfullname = @()
	$listinspectorsname = @()
	
	if ($CustomModules -eq $true)
	{
		foreach ($Module in $Modules)
		{
			Get-ChildItem -Path $Directory\$Module\$Folder -Recurse | Unblock-File
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			foreach ($inspector in $AllInspectors)
			{
				$fullname = $inspector.FullName
				$name = ($inspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
			}
			
			Get-ChildItem -Path $Directory\$Module\CUSTOM -Recurse | Unblock-File
			$AllCustomInspectors = Get-ChildItem $Directory\$Module\CUSTOM\*.ps1
			foreach ($custominspectors in $AllCustomInspectors)
			{
				$customfullname = $custominspectors.FullName
				$customname = ($custominspectors.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $customfullname; 'Name' = $customname })
			}
		}
	}
	else
	{
		foreach ($Module in $Modules)
		{
			Get-ChildItem -Path $Directory\$Module\$Folder -Recurse | Unblock-File
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			foreach ($inspector in $AllInspectors)
			{
				$fullname = $inspector.FullName
				$name = ($inspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
			}
		}
	}
	$listinspectors = [PSCustomObject]@{
		Inspectors = $listfullinspectors
	}
	
	return $listinspectors
	
}