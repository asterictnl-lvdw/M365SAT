# . "..\M365SAT.psm1"
function Get-M365SATCSVReport
{
	Param ($object,
		$OutPath,
		$inspectors)

        # Initalize Dates
        $StartDate = $object.StartDate
        $ReportDate = $object.EndDate

        # Sort all findings
        $SortedFindings = $object.Findings | Sort-Object $_.ID

        #CompanyName
        try{
            # Microsoft Graph Variant
            $CompanyName = (Get-MgOrganization).DisplayName
            $TenantName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
        }catch{
            # Microsoft Exchange Variant
            $CompanyName = (Get-AcceptedDomain | Where-Object { $_.Default -eq 'True' }).DomainName
            $TenantName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
        }

        # Initialize Empty List
        $FinalFindings = @()

        # Create a count of findings
        $FindingCounter = 0

        foreach ($finding in $SortedFindings){
            if ($null -NE $finding.ReturnedValue){
                $FindingCounter += 1

                # Create empty list for References
                $refs = New-Object System.Collections.ArrayList
                foreach ($Reference in $finding.References){
                    $refs.Add("$($Reference.Name) : $($Reference.URL)") | Out-Null
                }
                $finalrefs = $refs -join '^'
                $refs.Clear()
            }
            $result = [PSCustomObject]@{
                UUID                 = $finding.UUID
                ID			         = $finding.ID
                Title                = $finding.Title
                ProductFamily        = $finding.ProductFamily
                DefaultValue	     = $finding.DefaultValue
                ExpectedValue        = $finding.ExpectedValue
                ReturnedValue        = $("$($finding.ReturnedValue)" | Out-String).Trim()
                'Remediation Status' = $finding.Status
                'Notes'              = " "
                Description	         = $finding.Description
                Impact               = $finding.Impact
                Remediation          = $(($finding.Remediation) -join " ")
                References           = $finalrefs
            }
            $FinalFindings += $result
        }

	# Write to file
	
	# Create a new directory for the new report
	$NewPath = New-CreateDirectory($OutPath)
	$LogPath = "$($NewPath)\evidence"
    New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

	#Move All Logs into the newly created path
	$LogFiles = (Get-ChildItem -Path $OutPath -Filter "*.txt").FullName
	foreach ($LogFile in $LogFiles)
	{
		Move-Item -Path $LogFile -Destination $LogPath -Force
	}

    $ReportFileName = "M365SAT-$(Get-Date -Format 'yyyyMMddHHmm').csv"
    $OutputFile = "$NewPath\$ReportFileName"

    $FinalFindings | Export-Csv $OutputFile -Delimiter '^' -NoTypeInformation -Append -Force

    #Create a .zip File of the full report including the objects
	New-ZipFile($NewPath)
	
	# Open the HTML Report
	Close-Logger
	Invoke-Expression $OutputFile
}

function New-ZipFile($outpath)
{
	try
	{
		$compress = @{
			Path			 = $OutPath
			CompressionLevel = "Fastest"
			DestinationPath  = "$OutPath\$($TenantName)_Report_$(Get-Date -Format "yyyy-MM-dd_hh-mm-ss").zip"
		}
		Compress-Archive @compress
	}
	catch
	{
		'File Already Exists!'
	}
}

function New-CreateDirectory($OutPath)
{
	#Create Output Directory if required
	if (Test-Path -Path $OutPath)
	{
		Write-Host "Path Exists! Checking Permissions..."
		try
		{
			Write-Host "Creating Directory..."
			$newpath = "$OutPath\$($TenantName)_$(Get-Date -Format "yyyyMMddhhmmss")"
			New-Item -ItemType Directory -Force -Path $newpath | Out-Null
			$path = Resolve-Path $newpath
			return $newpath
		}
		catch
		{
			Write-Error "Could not create directory"
			break
		}
	}
	else
	{
		Write-Host "Path does not exist! Creating Directory..."
		try
		{
			Write-Host "Creating Parent Directory..."
			New-Item -ItemType Directory -Force -Path $OutPath | Out-Null
			$newpath = "$OutPath\$($TenantName)_$(Get-Date -Format "yyyyMMddhhmmss")"
			Write-Host "Creating Report Directory..."
			New-Item -ItemType Directory -Force -Path $newpath | Out-Null
			$path = Resolve-Path $newpath
			return $newpath
		}
		catch
		{
			Write-Error "Could not create Directory! Insufficient Permissions!"
			break
		}
	}
}