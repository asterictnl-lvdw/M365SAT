function Run-M365SATLocalInspectors
{
	
	Param ($inspectors,
		$Directory)
	
	$startdate = (Get-Date) # This is the actual start time of the security assessment
	# Get a list of every available detection module by parsing the PowerShell
	# scripts present in the .\inspectors folder. 
	#Exclude specified Inspectors
	
	if ($excluded_inspectors.Count -ne 0)
	{
		Write-Host "The following Inspectors have been excluded from execution: "
		$excluded_inspectors = foreach ($excluded_inspector in $excluded_inspectors)
		{
			Write-Host "$excluded_inspector.ps1"
		}
		$inspectors = (Get-ChildItem $Directory\*.ps1 -Exclude $excluded_inspectors).Name | ForEach-Object { ($_ -split ".ps1")[0] }
	}
	elseif ($selected_inspectors.Count -ne 0)
	{
		$selected_inspector_list = @()
		Write-Host "The following Inspectors were selected for use: "
		foreach ($selected_inspector in $selected_inspectors)
		{
			Write-Host "$($selected_inspector)"
			$selected_inspector_list += $selected_inspector
		}
	}
	else
	{
		Write-Host "Using all inspectors!"
		$selected_inspectors = $inspectors
	}
	
	
	# Maintain a list of all findings, beginning with an empty list.
	$findings = @()
	
	# For every inspector the user wanted to run...
	foreach ($selected_inspector in $selected_inspectors) # Just a dummy to check if inspector List is ingested correctly
	{
		try
		{
			if ($inspectors.Contains($selected_inspector))
			{
				Write-Host "Executing Inspector: $selected_inspector ..."
				
				# Invoke the actual inspector module and store the resulting list of insecure objects.
				$finding = Invoke-Expression "$Directory\$selected_inspector.ps1"
				
				# Add the finding to the list of all findings. But do check if the Finding is not null, else it is useless to add.
				if ($finding -ne $null)
				{
					Write-Host "Violation Found!" -ForegroundColor Red
					$findings += $finding
				}
				else
				{
					Write-Host "Did not found any violation!" -ForegroundColor Green
				}
			}
		}
		catch
		{
			Exception
		}
		
	}
	$executeinspectorsobject = New-Object PSObject -Property @{
		Findings   = $findings
		StartDate  = $startdate
		Inspectors = $selected_inspectors
	}
	return $executeinspectorsobject
}

function Run-M365SATInspectors($inspectors)
{
	$startdate = (Get-Date) # This is the actual start time of the security assessment
	# Get a list of every available detection module by parsing the PowerShell
	# scripts present in the .\inspectors folder. 
	#Exclude specified Inspectors
	
	if ($excluded_inspectors.Count -ne 0)
	{
		Write-Host "The following Inspectors have been excluded from execution: "
		$excluded_inspectors = foreach ($excluded_inspector in $excluded_inspectors)
		{
			Write-Host "$excluded_inspector.ps1"
		}
		$inspectors = (Get-ChildItem $env:TEMP\inspector\*.ps1 -Exclude $excluded_inspectors).Name | ForEach-Object { ($_ -split ".ps1")[0] }
	}
	elseif ($selected_inspectors.Count -ne 0)
	{
		$selected_inspector_list = @()
		Write-Host "The following Inspectors were selected for use: "
		foreach ($selected_inspector in $selected_inspectors)
		{
			Write-Host "$($selected_inspector)"
			$selected_inspector_list += $selected_inspector
		}
	}
	else
	{
		Write-Host "Using all inspectors!"
		$selected_inspectors = $inspectors
	}
	
	# Maintain a list of all findings, beginning with an empty list.
	$findings = @()
	
	# For every inspector the user wanted to run...
	foreach ($selected_inspector in $selected_inspectors)
	{
		try
		{
			# ...if the user selected a valid inspector...
			if ($inspectors.Contains($selected_inspector))
			{
				Write-Host "Executing Inspector: $selected_inspector ..."
				
				# Invoke the actual inspector module and store the resulting list of insecure objects.
				$finding = Invoke-Expression "$env:TEMP\inspectors\$selected_inspector.ps1"
				
				# Add the finding to the list of all findings. But do check if the Finding is not null, else it is useless to add.
				# Add the finding to the list of all findings. But do check if the Finding is not null, else it is useless to add.
				if ($finding -ne $null)
				{
					Write-Host "Violation Found!" -ForegroundColor Red
					$findings += $finding
				}
				else
				{
					Write-Host "Did not found any violation!" -ForegroundColor Green
				}
			}
		}
		catch
		{
			Exception
		}
	}
	$executeinspectorsobject = New-Object PSObject -Property @{
		Findings   = $findings
		StartDate  = $startdate
		Inspectors = $selected_inspectors
	}
	return $executeinspectorsobject
}

function Exception
{
	if (-not (Get-Variable -Name 'PSScriptRoot' -Scope 'Script'))
	{
		$Script:PSScriptRoot = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
	}
	if ($psISE)
	{
		.(Join-Path (Split-Path -Path $psISE.CurrentFile.FullPath) Write-ErrorLog.ps1)
	}
	else
	{
		.(Join-Path $PSScriptRoot Write-ErrorLog.ps1)
	}
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
	Write-ErrorLog -Message $message -Exception $exception -scriptname $scriptname -failinglinenumber $failinglinenumber -failingline $failingline -pscommandpath $pscommandpath -positionmsg $pscommandpath -stacktrace $strace
	Write-Verbose "Errors written to log"
}