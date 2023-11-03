<# Downloads all Inspectors and creates list #>
function Get-M365SATChecks($Directory, $Modules, $CustomModules, $AuditType)
{
	<# This is only for the Online Version. And is in beta, this script will be improved upon future releases #>
<# Downloads the Inspectors from Github and extracts them to the powershellmodule location #>
	Invoke-WebRequest 'https://github.com/asterictnl-lvdw/M365SAT-inspectors/archive/refs/heads/main.zip' -OutFile $Directory\inspectors.zip
	# Name of the Directory
	Expand-Archive $Directory\inspectors.zip
	Rename-Item $Directory\365inspect-main $Directory
	Get-ChildItem -Path $Directory -Recurse | Unblock-File #So no problems will occur when trying to execute inspectors
	$tempfiles += "$Directory\inspectors.zip"
<# Creates List of All Inspectors #>
	
	if ($Modules.Contains("All"))
	{
		$Modules = @("MicrosoftAzure", "MicrosoftExchange", "MicrosoftOffice365", "MicrosoftSharepoint", "MicrosoftTeams")
	}
	
	if ($AuditType.Contains("CISV3"))
	{
		$Folder = "CIS30"
	}
	else
	{
		$Folder = "CIS20"
	}
	
	$AzureFolder = "CISA20"
	
	#Empty Lists Initialization
	$listfullinspectors = @()
	$listinspectorsfullname = @()
	$listinspectorsname = @()
	
	
	
	if ($CustomModules -eq $true)
	{
		foreach ($Module in $Modules)
		{
			# Unblock all files if neccesary
			Get-ChildItem -Path $Directory\$Module\$Folder -Recurse | Unblock-File
			Get-ChildItem -Path $Directory\$Module\CUSTOM -Recurse | Unblock-File
			
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			
			$AllCustomInspectors = Get-ChildItem $Directory\$Module\CUSTOM\*.ps1
			
			#AllInspectors executed multiple times
			foreach ($inspector in $AllInspectors)
			{
				$fullname = $inspector.FullName
				$name = ($inspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
			}
			
			# Azure is executed only once
			if ($Module.Contains("MicrosoftAzure"))
			{
				Get-ChildItem -Path $Directory\$Module\$AzureFolder -Recurse | Unblock-File
				$AzureInspectors = Get-ChildItem $Directory\$Module\$AzureFolder\*ps1
				foreach ($azureinspector in $AzureInspectors)
				{
					$azurefullname = $azureinspector.FullName
					$azurename = ($azureinspector.Name -split ".ps1")[0]
					$listfullinspectors += @(@{ 'FullName' = $azurefullname; 'Name' = $azurename })
				}
			}
			
			foreach ($custominspector in $AllCustomInspectors)
			{
				$customfullname = $custominspector.FullName
				$customname = ($custominspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $customfullname; 'Name' = $customname })
			}
		}
	}
	else
	{
		foreach ($Module in $Modules)
		{
			Get-ChildItem -Path $Directory\$Module\$Folder -Recurse | Unblock-File
			Get-ChildItem -Path $Directory\$Module\CUSTOM -Recurse | Unblock-File
			
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			
			# Azure is executed only once
			if ($Module.Contains("MicrosoftAzure"))
			{
				Get-ChildItem -Path $Directory\$Module\$AzureFolder -Recurse | Unblock-File
				$AzureInspectors = Get-ChildItem $Directory\$Module\$AzureFolder\*ps1
				foreach ($azureinspector in $AzureInspectors)
				{
					$azurefullname = $azureinspector.FullName
					$azurename = ($azureinspector.Name -split ".ps1")[0]
					$listfullinspectors += @(@{ 'FullName' = $azurefullname; 'Name' = $azurename })
				}
			}
			
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

function Get-M365SATLocalChecks($Directory, $Modules, $CustomModules, $AuditType)
{
	if ($Modules.Contains("All"))
	{
		$Modules = @("MicrosoftAzure", "MicrosoftExchange", "MicrosoftOffice365", "MicrosoftSharepoint", "MicrosoftTeams")
	}
	
	if ($AuditType.Contains("CISV3"))
	{
		$Folder = "CIS30"
	}
	else
	{
		$Folder = "CIS20"
	}
	
	$AzureFolder = "CISA20"
	
	#Empty Lists Initialization
	$listfullinspectors = @()
	$listinspectorsfullname = @()
	$listinspectorsname = @()
	
	if ($CustomModules -eq $true)
	{
		foreach ($Module in $Modules)
		{
			# Unblock all files if neccesary
			Get-ChildItem -Path $Directory\$Module\$Folder -Recurse | Unblock-File
			Get-ChildItem -Path $Directory\$Module\CUSTOM -Recurse | Unblock-File
			
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			
			$AllCustomInspectors = Get-ChildItem $Directory\$Module\CUSTOM\*.ps1
			
			#AllInspectors executed multiple times
			foreach ($inspector in $AllInspectors)
			{
				$fullname = $inspector.FullName
				$name = ($inspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $fullname; 'Name' = $name })
			}
			
			# Azure is executed only once
			if ($Module.Contains("MicrosoftAzure"))
			{
				Get-ChildItem -Path $Directory\$Module\$AzureFolder -Recurse | Unblock-File
				$AzureInspectors = Get-ChildItem $Directory\$Module\$AzureFolder\*ps1
				foreach ($azureinspector in $AzureInspectors)
				{
					$azurefullname = $azureinspector.FullName
					$azurename = ($azureinspector.Name -split ".ps1")[0]
					$listfullinspectors += @(@{ 'FullName' = $azurefullname; 'Name' = $azurename })
				}
			}
			
			foreach ($custominspector in $AllCustomInspectors)
			{
				$customfullname = $custominspector.FullName
				$customname = ($custominspector.Name -split ".ps1")[0]
				$listfullinspectors += @(@{ 'FullName' = $customfullname; 'Name' = $customname })
			}
		}
	}
	else
	{
		foreach ($Module in $Modules)
		{
			Get-ChildItem -Path $Directory\$Module\$Folder -Recurse | Unblock-File
			Get-ChildItem -Path $Directory\$Module\CUSTOM -Recurse | Unblock-File
			
			$AllInspectors = Get-ChildItem $Directory\$Module\$Folder\*.ps1
			
			# Azure is executed only once
			if ($Module.Contains("MicrosoftAzure"))
			{
				Get-ChildItem -Path $Directory\$Module\$AzureFolder -Recurse | Unblock-File
				$AzureInspectors = Get-ChildItem $Directory\$Module\$AzureFolder\*ps1
				foreach ($azureinspector in $AzureInspectors)
				{
					$azurefullname = $azureinspector.FullName
					$azurename = ($azureinspector.Name -split ".ps1")[0]
					$listfullinspectors += @(@{ 'FullName' = $azurefullname; 'Name' = $azurename })
				}
			}
			
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