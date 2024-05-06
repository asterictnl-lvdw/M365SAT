# . "..\M365SAT.psm1"

function Get-M365SATHTMLReport
{
	Param ($object,
		$OutPath,
		$inspectors)
	
	# All Attributes must be stated below
	#Inititialize RootObject Dummy
	$Icons = @("https://shorturl.at/hlqvV", "https://shorturl.at/kquU1", "https://shorturl.at/pzVX6", "https://shorturl.at/xyHT9", "https://shorturl.at/rFMNO")
	$ProductFamilies = @("Microsoft Teams", "Microsoft Exchange", "Microsoft Azure", "Microsoft Sharepoint", "Microsoft Office 365")
	$i = 0

    try{
        # Microsoft Graph Variant
        $CompanyName = (Get-MgOrganization).DisplayName
        $TenantName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
    }catch{
        # Microsoft Exchange Variant
        $CompanyName = (Get-AcceptedDomain | Where-Object { $_.Default -eq 'True' }).DomainName
        $TenantName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
    }
	
	#Initialize Objects
	$ExchangeObject = @()
	$TeamsObject = @()
	$AzureObject = @()
	$SharepointObject = @()
	
	#AffectedObjects Definition
	$AffectedObjects = $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.Priority -and $_.RiskRating -ne $null } }).Count
	$ExchangeObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Exchange" -and $_.RiskRating -ne $null } })
	$AzureObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Azure" -and $_.RiskRating -ne $null } })
	$TeamsObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Teams" -and $_.RiskRating -ne $null } })
	$SharePointObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Sharepoint" -and $_.RiskRating -ne $null } })
	$MO365Object += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Office 365" -and $_.RiskRating -ne $null } })
	
	# Obtain the tenant domain and date for the report
	
	$StartDate = $object.StartDate
	$ReportDate = $object.EndDate
	$Version = "2.2 alpha"
	
	# Summary (Critical,High,Medium,Low,Informational)
	
	$CriticalCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.RiskRating -eq "Critical" } }).RiskRating.Count
	$HighCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.RiskRating -eq "High" } }).RiskRating.Count
	$MediumCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.RiskRating -eq "Medium" } }).RiskRating.Count
	$LowCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.RiskRating -eq "Low" } }).RiskRating.Count
	$InformationalCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.RiskRating -eq "Informational" } }).RiskRating.Count
	
	# Misc
	$ReportTitle = "M365SAT - Microsoft 365 Security Report"
	$ReportSub1 = "M365SAT - Microsoft 365 Security Assessment Tool"
	$ReportSub2 = "Security Audit Report"
	$ReportSub3 = "This report details any tenant configuration changes recommended within your tenant."
	
	# End of Attributes
	
	# Output start
	$Output = "<!doctype html>
    <html lang='en'>
    <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>
        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css' crossorigin='anonymous'>
        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css' crossorigin='anonymous'>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/2.11.8/umd/popper.min.js' crossorigin='anonymous'></script>
        <script src='https://code.jquery.com/jquery-3.7.0.slim.js' integrity='sha256-7GO+jepT9gJe9LB4XFf8snVOjX3iYNb0FHYr5LI1N5c=' crossorigin='anonymous'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.js'></script>
        <!-- To be fixed:-->
        <script src='https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.0.0/js/bootstrap.min.js' crossorigin='anonymous'></script>
        <script src='https://cdn.jsdelivr.net/npm/clipboard@2.0.11/dist/clipboard.min.js'></script>

        <style>
        html, body {
            min-height: 100%;
        }

        .accordion-button{
            border: 2px solid #dee2e63b;
        }

        .tooltip {
            position: relative;
            display: contents;
        }

        pre[class*=""language-""] button {
            position: absolute;
            right: 37px;
        }

        @media (min-width: 576px)
        .col-sm-4 {
            flex: 0 0 auto;
        }

        .tooltip .tooltiptext {
        visibility: hidden;
        width: 140px;
        background-color: #555;
        color: #fff;
        text-align: center;
        border-radius: 6px;
        padding: 5px;
        position: absolute;
        z-index: 1;
        bottom: 150%;
        left: 50%;
        margin-left: -75px;
        opacity: 0;
        transition: opacity 0.3s;
        }

        .tooltip .tooltiptext::after {
        content: '';
        position: absolute;
        top: 100%;
        left: 50%;
        margin-left: -5px;
        border-width: 5px;
        border-style: solid;
        border-color: #555 transparent transparent transparent;
        }

        .tooltip:hover .tooltiptext {
        visibility: visible;
        opacity: 1;
        }

        .header-bar{
            display: flex;
        }

        .navbar-custom { 
            background-color: #005494;
            color: white; 
            padding-bottom: 10px;

            
        } 
        /* Modify brand and text color */ 
          
        .navbar-custom .navbar-brand, 
        .navbar-custom .navbar-text { 
            color: white; 
            padding-top: 70px;
            padding-bottom: 10px;

        } 

        .summary-header{
            background-color: #ffffff2e;
            color: white;
        }

        .m-2 {
            overflow-y: scroll;
            height: 350px;
        }

		.m-3 {
			margin: 0.1rem!important;
			word-break: break-word;
		}
        .card-header {
            background-color: #0078D4;
            color: white; 
        }

        .card-prio-info{
            background-color: #2986CC;
            color: white;
            border-color: #2986CC;
        }

        .card-prio-low{
            background-color: #38761D;
            color: white;
            border-color: #38761D;
        }

        .card-prio-medium{
            background-color: #FFC107;
            color: white;
            border-color: #FFC107;
        }

        .card-prio-high{
            background-color: #FF1100;
            color: white;
            border-color: #FF1100;
        }

        .card-prio-critical{
            background-color: #660000;
            color: white;
            border-color: #660000;
        }

        .table-row-column {
            float: left;
            width: auto;
            padding: 5px;
        }

        .table-summary-results{
            width:fit-content;
        }

        .table-results{
            width:auto;
        }

        table{
            table-layout: fixed;
        }
       
        .table-borderless td,
        .table-borderless th {
            border: 0;
            padding:5px; 

        }
        .bd-callout {
            padding: 1.25rem;
            border: 1px solid #f8f9fa;
            border-left-width: .25rem;
            border-radius: .25rem;
        }
        
        .bd-callout h4 {
            margin-top: 0;
            margin-bottom: .25rem;
        }
        
        .bd-callout p:last-child {
            margin-bottom: 0;
        }
        
        .bd-callout code {
            border-radius: .25rem;
        }
        
        .bd-callout+.bd-callout {
            margin-top: -.25rem;
        }
        
        .bd-callout-info {
            border-left-color: #5bc0de;
        }
        
        .bd-callout-info h4 {
            color: #5bc0de;
        }
        
        .bd-callout-warning {
            border-left-color: #f0ad4e;
        }
        
        .bd-callout-warning h4 {
            color: #f0ad4e;
        }
        
        .bd-callout-danger {
            border-left-color: #d9534f;
        }
        .bd-callout-critical {
            border-left-color: #660000;
        }
        .bd-callout-critical h4 {
            color: #660000;
        }
        .bd-callout-danger h4 {
            color: #d9534f;
        }
        .bd-callout-success {
            border-left-color: #00bd19;
        }
        .bg-critical{
            background-color: #660000;
        }
        .app-footer{
            background-color: #005494;
            color: white; 
            padding-top:2px; 
            padding-bottom :2px; 
        }
        .star-cb-group {
            /* remove inline-block whitespace */
            font-size: 0;
            /* flip the order so we can use the + and ~ combinators */
            unicode-bidi: bidi-override;
            direction: rtl;
            /* the hidden clearer */
        }
        .star-cb-group * {
            font-size: 1rem;
        }

        .card-body{
            overflow:auto;
        }

        .star-cb-group > input {
            display: none;
        }
        .star-cb-group > input + label {
            /* only enough room for the star */
            display: inline-block;
            overflow: hidden;
            text-indent: 9999px;
            width: 1.7em;
            white-space: nowrap;
            cursor: pointer;
        }
        .star-cb-group > input + label:before {
            display: inline-block;
            text-indent: -9999px;
            content: ""\2606"";
            font-size: 30px;
            color: #005494;
        }
        .star-cb-group > input:checked ~ label:before, .star-cb-group > input + label:hover ~ label:before, .star-cb-group > input + label:hover:before {
            content:""\2605"";
            color: #e52;
            font-size: 30px;
            text-shadow: 0 0 1px #333;
        }
        .star-cb-group > .star-cb-clear + label {
            text-indent: -9999px;
            width: .5em;
            margin-left: -.5em;
        }
        .star-cb-group > .star-cb-clear + label:before {
            width: .5em;
        }
        .star-cb-group:hover > input + label:before {
            content: ""\2606"";
            color: #005494;
            font-size: 30px;
            text-shadow: none;
        }
        .star-cb-group:hover > input + label:hover ~ label:before, .star-cb-group:hover > input + label:hover:before {
            content: ""\2605"";
            color: #e52;
            font-size: 30px;
            text-shadow: 0 0 1px #333;
        }

        .finding-detail-value {
            padding-bottom: 50pt;
            color: #000000;
            text-decoration: none;
            vertical-align: baseline;
            font-size: 11pt;
            font-family: 'Source Sans Pro Light', 'Source Sans Pro';
            font-style: normal;
          }

        pre[class*=language-] {
            padding: 1em;
            margin: .5em 0;
        }

        .row{
            display: block;
            margin-right: -15px;
            margin-left: -15px;
        }

        </style>

        <title>$($ReportTitle)</title>

    </head>
    <body class='app bg-light'>
        <link href='https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism.min.css' rel='stylesheet' />
        <script src='https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-powershell.min.js'></script>
    	<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
    	<script src='https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.0.0'></script>
        
        <nav class='navbar navbar-custom' >
            <div class='container-fluid'>
                <div class='col-sm' style='text-align:left'>
                    <div class='header-bar'><div><i class='fa-solid fa-magnifying-glass'></i></div><div class='ml-3'><strong>$($ReportTitle)</strong></div></div>
                </div>
              
                <div class='col-sm' style='text-align:right'>
                <button type='button' class='btn btn-primary' onclick='javascript:window.print();'><i class='fa-solid fa-print'></i> Print This Report</button>
                 <BR/> 
               

                </div>
            </div>
        </nav>  
              <div class='app-body p-3'>
            <main class='main'>
                <!-- Main content here -->
                <div class='container' style='padding-top:10px;'></div>
                <div class='card'>
                        
                        <div class='card-body'>

                            <h2 class='card-title'>$($ReportTitle)</h2>"
	
	$Output += "<div style='text-align:right;margin-top:-65px;margin-right:8px;color:#005494;';>
				            <b>Rate this report</b>
					</div>
						
                         <div style='text-align:right;margin-top:-10px';>
             
                         <span class='star-cb-group'>
                            <input type='radio' id='rating-5' name='rating' value='5' onclick=""window.open('https://aka.ms/m365sat-feedback-5','_blank');"" />
                            <label for='rating-5'>5</label>
                            <input type='radio' id='rating-4' name='rating' value='4' onclick=""window.open('https://aka.ms/m365sat-feedback-4','_blank');"" />
                            <label for='rating-4'>4</label>
                            <input type='radio' id='rating-3' name='rating' value='3' onclick=""window.open('https://aka.ms/m365sat-feedback-3','_blank');"" />
                            <label for='rating-3'>3</label>
                            <input type='radio' id='rating-2' name='rating' value='2' onclick=""window.open('https://aka.ms/m365sat-feedback-2','_blank');"" />
                            <label for='rating-2'>2</label>
                            <input type='radio' id='rating-1' name='rating' value='1' onclick=""window.open('https://aka.ms/m365sat-feedback-1','_blank');"" />
                            <label for='rating-1'>1</label>
                            <input type='radio' id='rating-0' name='rating' value='0' class='star-cb-clear' />
                            <label for='rating-0'>0</label>
                            </span>
                         </div>
							"
	
	$Output += "<strong>Version $version </strong>
                            <p> M365SAT assesses your compliance posture, highlights risks and recommends remediation steps to ensure compliance with essential data protection and regulatory standards.</p>"
	
	$Output += "<table><tr><td>
                            <strong>Start Date</strong>  </td>
                            <td><strong>: $($StartDate)</strong>  </td>
                            </tr>
                           
                            "
	$Output += "<tr><td><strong>End Date</strong> </td>
                            <td><strong>: $($ReportDate)</strong>  </td>
                            </tr>
                           
                            "
	
	$Output += " <tr><td><strong>Organization &nbsp;</strong> </td>
                                             <td><strong>: $($CompanyName)</strong> </td></tr>
                                             "
	$Output += " <tr><td><strong>Tenant Name &nbsp;</strong> </td>
                             <td><strong>: $($TenantName)</strong> </td></tr>
                             "
	$Output += " <tr><td><strong>Stats &nbsp;</td></strong>
                             <td><strong>: $AffectedObjects</strong> out of <strong>$($object.InspectorsCount)</strong> executed inspector modules identified possible opportunities for improvement.</td></tr>
                             "
    $Output += " <tr><td><strong>HealthScore &nbsp;</strong> </td>
                            <td><strong>: $([math]::Round(100 - (($AffectedObjects/$object.InspectorsCount) * 100)))%</strong></td></tr>
                            "
	
	$Output += "  </table>"
	
	
	$Output += "<br/>"
	
	<#

        OUTPUT GENERATION / Summary cards

    #>
	
	$Output += "
                    <table class='table-summary-results'>
                        <td>    
                            <div class='col d-flex justify-content-center text-center'>
                                <div class='card card-prio-info mb-3' style='width: 10em;'>
                                    <div class='summary-header'><h6>Informational</h6></div>
                                    <div class='card-body'>
                                    <h3>$($InformationalCount)</h3>
                                    </div>
                                </div>
                            </div>
                        </td>
                    "
	
	$Output += "
                <td>
                    <div class='col d-flex justify-content-center text-center'>
                            <div class='card card-prio-low mb-3' style='width: 10rem;'>
                            <div class='summary-header'><h6>Low</h6></div>
                            <div class='card-body'>
                            <h3>$($LowCount)</h3>
                            </div>
                        </div>
                    </div>
                </td>
                <td>
                    <div class='col d-flex justify-content-center text-center'>
                        <div class='card card-prio-medium mb-3' style='width: 10rem;'>
                            <div class='summary-header'><h6>Medium</h6></div>
                            <div class='card-body'>
                            <h3>$($MediumCount)</h3>
                        </div>
                    </div>
                </div>
                </td>"
	
	$Output += "
                <td>
                <div class='col d-flex justify-content-center text-center'>
                    <div class='card card-prio-high mb-3' style='width: 10rem;'>
                        <div class='summary-header'><h6>High</h6></div>
                        <div class='card-body'>
                        <h3>$($HighCount)</h3>
                        </div>
                    </div>
                </div>
                </td>
                <td>
                <div class='col d-flex justify-content-center text-center'>
                    <div class='card card-prio-critical mb-3' style='width: 10rem;'>
                        <div class='summary-header'><h6>Critical</h6></div>
                        <div class='card-body'>
                        <h3>$($CriticalCount)</h3>
                        </div>
                    </div>
                </div>
            </td></table>"
	
    <#
    
                OUTPUT GENERATION / Config Health Index

    #>
	
	$Output += "
    <div class='card m-3'>

        <div class='card-body'>
            <div class='row'>
                <div class='col-sm-4 text-center align-self-center'>

                    <div class='progress' style='height: 40px'>
                        <div class='progress-bar progress-bar-striped bg-info' role='progressbar' style='width: $([math]::Round(100 - (($AffectedObjects/$object.InspectorsCount) * 100)))%;' aria-valuenow='$([math]::Round(100 - (($AffectedObjects/$object.InspectorsCount) * 100)))' aria-valuemin='0' aria-valuemax='100'><h2>$([math]::Round(100 - (($AffectedObjects/$object.InspectorsCount) * 100)))%</h2></div>
                    </div>
                
                </div>
                <div class='col-sm-8'>
                    <h6>Configuration Health Index</h6>                  
                    <p>The configuration health index is a weighted value representing your configuration. Not all configuration is 
                    considered the same. Some configuration is weighted higher than others. <a href='https://github.com/karmakstylez/M365SAT' target='_blank'>See More... </a></p>

                </div>
            </div>                    
    </div>
  
    
    "
	
	
	
        <#
    
        OUTPUT GENERATION / Summary

    #>
	
	$Output += "
    <div class='card m-3'>
    <a name='Solutionsummary' id='Solutionsummary'></a>

        <div class='card-header'>
          Solutions Summary
        </div>
        <div class='card-body'>
        <div class='table-row-column'>"
	$Output += "<table class='table-results table-borderless'>
        <tr>
            <td width='20'><i class='fa-solid fa-check'></i>
            <td><strong>All Solutions</strong></td>
            <td align='right'>
                <span title='Informational' class='badge card-prio-info' style='padding:15px;text-align:center;width:40px;"; $Output += "'>$($InformationalCount)</span>
                <span title='Low' class='badge card-prio-low' style='padding:15px;text-align:center;width:40px;"; $Output += "'>$($LowCount)</span>
                <span title='Medium' class='badge card-prio-medium' style='padding:15px;text-align:center;width:40px;"; $Output += "'>$($MediumCount)</span>
				<span title='High' class='badge card-prio-high' style='padding:15px;text-align:center;width:40px;"; $Output += "'>$($HighCount)</span>
				<span title='Critical' class='badge card-prio-critical' style='padding:15px;text-align:center;width:40px;"; $Output += "'>$($CriticalCount)</span>
            </td>
        </tr>
        "
	
	ForEach ($Productfamily in $ProductFamilies)
	{
		#Reset Values each time new Product family is introduced
		$Critical = 0
		$High = 0
		$Medium = 0
		$Low = 0
		$Info = 0
		
		$Products = $(foreach ($Product in $object.Findings) { $Product | ? { $_.ProductFamily -eq $Productfamily } })
		foreach ($Prod in $Products)
		{
			if ($Prod.RiskRating -eq "Critical")
			{
				$Critical++
			}
			elseif ($Prod.RiskRating -eq "High")
			{
				$High++
			}
			elseif ($Prod.RiskRating -eq "Medium")
			{
				$Medium++
			}
			elseif ($Prod.RiskRating -eq "Low")
			{
				$Low++
			}
			elseif ($Prod.RiskRating -eq "Informational")
			{
				$Info++
			}
			else
			{
				continue
			}
		}
		$Output +=
		"
            <tr>
                <td width='20'>
                <td style='vertical-align:middle;'><img src='$($Icons[$i])' style='width: 16px; height: 16px' title='$($Productfamily)'>&nbsp;&nbsp; <a href='`#$($Productfamily.Replace(" ", "_"))'>$($Productfamily)</a></td>
                <td align='right' style='vertical-align:middle;'>
                <span class='badge card-prio-info' style='padding:10px;text-align:center;width:30px;";
		$Output += "'>$($Info)</span>
                <span class='badge card-prio-low' style='padding:10px;text-align:center;width:30px;";
		$Output += "'>$($Low)</span>
                <span class='badge text-white card-prio-medium' style='padding:10px;text-align:center;width:30px;";
		$Output += "'>$($Medium)</span>
                <span class='badge card-prio-high' style='padding:10px;text-align:center;width:30px;";
		$Output += "'>$($High)</span>
                <span class='badge text-white card-prio-critical' style='padding:10px;text-align:center;width:30px;";
		$Output += "'>$($Critical)</span>
                </td>
            </tr>
            "
		$i++
	}
	
	#Legenda Information
	$Output += "
    <tr><td colspan='3' style='text-align:right'> 
        <span title='Informational' class='badge card-prio-info'style='padding:5px;text-align:center'> </span>Informational
        <span title='Low' class='badge card-prio-low'style='padding:5px;text-align:center'> </span>Low
        <span title='Medium' class='badge card-prio-medium' style='padding:5px;text-align:center'> </span>Medium
        <span title='High' class='badge card-prio-high' style='padding:5px;text-align:center'> </span>High
        <span title='Critical' class='badge card-prio-critical' style='padding:5px;text-align:center'> </span>Critical
    </td></tr></table>"
	$Output += "
            </div>"

    #In case you want more statistics you can add them here, just copy this $Output part underneath it.
    <#
    $Output +="<div class='table-row-column'>
    </div>
    " 
    #>

    $Output += "        
        </div>
    </div>
    "
	
        <#

        OUTPUT GENERATION / Zones

    #>
	

	
	ForEach ($Productfamily in $ProductFamilies)
	{
		$Products = $(foreach ($Product in $object.Findings) { $Product | ? { $_.ProductFamily -eq $Productfamily } }) | Sort-Object -Descending { Switch -Regex ($_.RiskRating) { 'Critical' { 1 }	'High' { 2 } 'Medium' { 3 }	'Low' { 4 }	'Informational' { 5 } }; $_.RiskScore }
		#$Products = $(foreach ($Product in $object.Findings) { $Product | ? { $_.ProductFamily -eq $Productfamily } }) | Sort-Object -Property {[decimal]$_.CVS}
		$CollapseId = $($Productfamily).Replace(" ", "_")
		$Output += "<a name='$($Productfamily)'></a> 
        <div class='card m-3'>
            <div class='accordion' id='$($ProductFamily)_Acd'>
            <button class='accordion-button btn-align-left collapsed' type='button' id='$($CollapseId)' data-bs-toggle='collapse' data-bs-target='#$($CollapseId)_body' aria-controls='#$($CollapseId)_body'>$($Productfamily)</button>
            
            <div class='card-body accordion-collapse collapse' id='$($CollapseId)_body'>"
		
		ForEach ($Result in $Products)
		{
			$RemediationActionsExist = $false
			# Validation if result corresponds with severity
			If ($Result.RiskRating -eq "Informational")
			{
				$CalloutType = "bd-callout-info"
				$BadgeType = "card-prio-info"
				$BadgeName = "Informational"
				$Icon = "fas fa-thumbs-up"
				$IconColor = "#2986CC"
				$Title = $Check.PassText
			}
			ElseIf ($Result.RiskRating -eq "Low")
			{
				$CalloutType = "bd-callout-success"
				$BadgeType = "card-prio-low"
				$BadgeName = "Low"
				$Icon = "fas fa-thumbs-up"
				$IconColor = "#38761D"
				$Title = $Check.PassText
			}
			ElseIf ($Result.RiskRating -eq "Medium")
			{
				$CalloutType = "bd-callout-warning"
				$BadgeType = "card-prio-medium"
				$BadgeName = "Medium"
				$Icon = "fas fa-thumbs-down"
				$IconColor = "#FFC107"
				$Title = $Check.FailRecommendation
			}
			ElseIf ($Result.RiskRating -eq "High")
			{
				$CalloutType = "bd-callout-danger"
				$BadgeType = "card-prio-high"
				$BadgeName = "High"
				$Icon = "fas fa-thumbs-down"
				$IconColor = "#FF1100"
				$Title = $Check.FailRecommendation
			}
			Else
			{
				$CalloutType = "bd-callout-critical"
				$BadgeType = "card-prio-critical"
				$BadgeName = "Critical"
				$Icon = "fas fa-thumbs-down"
				$IconColor = "#660000"
				$Title = $Check.FailRecommendation
			}
			#Write Collapse Object that contains the info
			$Output += "        
                    <div class='accordion' id='$($ProductFamily)_Acd'>
                    <button class='accordion-button btn-align-left collapsed' type='button' id='$($Result.ID)' data-bs-toggle='collapse' data-bs-target='#$($Result.ID)_body' aria-expanded='false' aria-controls='$($Result.ID)_body'><span class='badge $($BadgeType)'>$($BadgeName)</span><h6>[$($Result.RiskScore)]: $($Result.FindingName)</h6></button></div> 
                    "
			#Start of Container Generation Within group object (FindingName)
			$Output += "  
                    <div class='card-body accordion-collapse collapse' id='$($Result.ID)_body'>
                        <div class='bd-callout $($CalloutType) b-t-1 b-r-1 b-b-1 p-3' >
                            <div class='container-fluid'>
                                <div class='header-bar'>
                                    <div><i class='$($Icon)' color='$($IconColor)'></i></div>
                                    <div class='col-8'><h6>$($Result.FindingName)</h6></div>
                                   
                                </div>"
			$i++
			#Display Description below 
			# Result.ID is a test. If the Output is messed up, please remove!
			$Output += "
                       <a id='$($Result.ID)'></a>
					   <div><b>ID: $($Result.ID)</b></div>
                       <div class='row p-3'>
                            <div><b>Description:</b><p>$($Result.Description)</p></div>

                                </div>"
			
			# Remediation Explanation
			$Output += "<div class='row p-3'>
                            <div><b>Remediation:</b><p>$($Result.Remediation)</p></div>

                    </div>"
			
			# PowerShellScript
			$Output += "<div class='row p-3'>
                            <div><b>PowerShell Script:</b><p><pre><code class='language-powershell'>$($Result.PowershellScript)</code></pre></p></div>

                                </div>"
			
			#Table information that should contain default value, expected value, returned value
			# We should expand the results by showing a table of Config Data and Items
			$Output += "
                            <div class='row p-3'>
                            <b>Returned Value:</b>
                        "

            #Checks if remedation is possible (returning value from object
			
			if ($Result.ReturnedValue.Count -GT 10)
			{
                $fname = $Result.ID
				$Output += "
                                    <div><a href='$($fname).txt'>$($Result.ReturnedValue.Count) Affected Objects Identified<a/>.</div>
                                    </div>
                                    "
				
				$Result.ReturnedValue | Out-File -FilePath $OutPath\$fname.txt
			}
			else
			{
				ForEach ($Values in $Result.ReturnedValue)
				{
					$Output += "<div>$($Values)</div>"
				}
                $Output += "</div>"
			}

			$Output += "
                            <div class='row p-3'>
                            <b>Default Value:</b>
                        "

				ForEach ($DefaultValues in $Result.DefaultValue)
				{
					$Output += "<div>$($DefaultValues)</div>"
				}
            
            $Output += "</div>"


            $Output += "
                            <div class='row p-3'>
                            <b>Expected Value:</b>
                        "

				ForEach ($ExpectedValues in $Result.ExpectedValue)
				{
					$Output += "<div>$($ExpectedValues)</div>"
				}
            
            $Output += "</div>"
			
			# RiskRating Explanation
			$Output += "<div class='row p-3'>
                            <div><b>Impact:</b><p>$($Result.Impact)</p></div>

                    </div>"
			
			# Likelihood Explanation
			$Output += "<div class='row p-3'>
                            <div><b>Likelihood:</b><p>$($Result.Likelihood)</p></div>

                    </div>"
			
			# Likelihood Explanation
			$Output += "<div class='row p-3'>
                            <div><b>Priority:</b><p>$($Result.Priority)</p></div>

                    </div>"
			
			# Impact Score
			$Output += "
                            <div>
                            <b>RiskRating:</b>
                            <div class='badge $($BadgeType) badge-pill badge-light'><span>$($Result.RiskRating)</span></div>
                            </div>
                        "
			
			$Output += "<br><div><div><span style='vertical-align: left;'><b>References:</b></span></div>"
			
			# Last line for the References to put there
			
			Foreach ($Reference in $Result.References)
			{
				$Output += "
                                    <div><i class='fas fa-external-link-square-alt'></i>&nbsp;<a href='$($Reference.URL)' target=""blank"">$($Reference.Name)</a></div>"
			}
			
            <#
			$Output += "
                            
                                    <td><a class='btn btn-primary' href='$($RemediationReportFileName)' target='_blank' role='button'>Remediation Script</a></td>"
			#>

			#END OF THE REPORT OBJECT
			
			
			$Output += "
                            </div>"
			
			
			
			
			$Output += "
                            </div>
                        </div> </div> "
			$i++
		}
		
		# End the card
		$Output += "   <div class='col-sm' style='text-align:right; padding-right:10px;'>  <a href='#Solutionsummary'>Go to Solutions Summary</a></div>
            </div>
                      

        </div></div>"

        
	}
	
    	#Put here list of Inspector Modules Executed:
	$CollapseId = "Executed_Inspectors"
	$Output += "<a name='Executed Inspectors'></a> 
        <div class='accordion' id='ExecutedInspectorsAcd'>
            <button class='accordion-button collapsed' type='button' id='more_$($CollapseId)' data-bs-toggle='collapse' data-bs-target='#$($CollapseId)_body' aria-controls='Microsoft_Teams_body'>Executed Inspectors</button>   
        </div>"
	
	$Output += "<div class='card-body accordion-collapse collapse m-2' id='$($CollapseId)_body'>"
	
	ForEach ($Inspector in $object.Inspectors)
	{
		$Output += "<div class='col-sm-10' style='text-align:left; margin-top:auto; margin-bottom:auto;'><a href='#$($Inspector)'>$($Inspector)</a></div>"
	}
	
	$Output += "</div></div>"
        <#

        OUTPUT GENERATION / Footer

    #>
	
	$Output += "
            <div class='collapsebuttons'>
                <button class='btn btn-primary' onClick='expand();'>Expand All</button>
                <button class='btn btn-primary' onClick='collapse();'>Collapse All</button>
            </div> 
            </main>
            <center>Found a bug? Report it! <a href='https://github.com/karmakstylez/M365SAT'>GitHub</a></center>
            </div>
            <div class='alert alert-success pt-2' >
            <center>Like this report? Try similar reporting for Microsoft's Compliance solutions. Download <a href='https://aka.ms/orca-mcca-github' target='_blank'> Microsoft Compliance Config Analyzer (MCCA)</a></center>
             </div>
            <footer class='app-footer'>
            <p><center><i>&nbsp;&nbsp;&nbsp;&nbsp;Disclaimer: Recommendations from (M365SAT) should not be interpreted as a guarantee of compliance. It is up to you to evaluate and validate the effectiveness of customer controls per your regulatory environment. </br>
               </i></center> </p></footer>
            <script>
                window.addEventListener('DOMContentLoaded', function () {
                Prism.highlightAll();
            });
            </script>

            <script>
                function expand() {
                `$('.collapse').collapse('show');
                }
                function collapse() {
                `$('.collapse').collapse('hide');
                }   
            </script>

            <script>
                const copyIcon = '<i class=""fa-solid fa-copy""></i>';
                const checkIcon = '<i class=""fa-solid fa-check""></i>';

                // use a class selector if available
                let blocks = document.querySelectorAll('pre');

                blocks.forEach((block) => {
                // only add button if browser supports Clipboard API
                if (navigator.clipboard) {
                    let button = document.createElement('button');

                    button.innerHTML = copyIcon;
                    block.appendChild(button);

                    button.addEventListener('click', async () => {
                    await copyCode(block, button);
                    });
                }
                });

                async function copyCode(block, button) {
                let code = block.querySelector('code');
                let text = code.innerText;

                await navigator.clipboard.writeText(text);

                // visual feedback that task is completed
                button.innerHTML = copyIcon;

                setTimeout(() => {
                    button.innerHTML = checkIcon;
                }, 700);
                }
            </script>
        </body>
    </html>"
	
	
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
	
	
	#Assign specific value to html report
	$ReportFileName = "M365SAT-$(Get-Date -Format 'yyyyMMddHHmm').html"
	
	$OutputFile = "$NewPath\$ReportFileName"
	
	$Output | Out-File -FilePath $OutputFile
	
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

<#
START SIGNATURE BLOCK

END SIGNATURE BLOCK
#>