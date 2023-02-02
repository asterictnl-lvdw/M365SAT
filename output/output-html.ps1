#. "..\M365SAT.psm1"

$TenantDomain = (Get-AcceptedDomain | ? { $_.Default -eq 'True' }).DomainName
$Tenant = (Get-AcceptedDomain | ? { $_.Default -eq 'True' }).DomainName.Split('.')[0]

function Get-M365SATReportHTML
{
	Param ($object,
		$OutPath,
		$inspectors)
	
	
	# All Attributes must be stated below
	#Inititialize RootObject Dummy
	$Icons = @("https://shorturl.at/hlqvV", "https://shorturl.at/kquU1", "https://shorturl.at/pzVX6", "https://shorturl.at/xyHT9", "https://shorturl.at/nwAM2")
	$ProductFamilies = @("Microsoft Teams", "Microsoft Exchange", "Microsoft Azure", "Microsoft Sharepoint","Microsoft Office 365")
	$i = 0
	
	#Initialize Objects
	$ExchangeObject = @()
	$TeamsObject = @()
	$AzureObject = @()
	
	#AffectedObjects Definition
	$AffectedObjects = $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.Impact -and $_.RiskRating -ne $null } }).Count
	$ExchangeObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Exchange" -and $_.RiskRating -ne $null } })
	$AzureObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Azure" -and $_.RiskRating -ne $null } })
	$TeamsObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Teams" -and $_.RiskRating -ne $null } })
	$SharePointObject += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Sharepoint" -and $_.RiskRating -ne $null } })
	$MO365Object += $(foreach ($Affected in $object.Findings) { $Affected | ? { $_.ProductFamily -eq "Microsoft Office 365" -and $_.RiskRating -ne $null } })
	
	# Obtain the tenant domain and date for the report
	
	$StartDate = $object.StartDate
	$ReportDate = $(Get-Date -format 'dd-MMM-yyyy HH:mm')
	$Version = "1.0"
	
	# Summary (Critical,High,Medium,Low,Informational)
	
	$CriticalCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.Impact -eq "Critical" } }).Impact.Count
	$HighCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.Impact -eq "High" } }).Impact.Count
	$MediumCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.Impact -eq "Medium" } }).Impact.Count
	$LowCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.Impact -eq "Low" } }).Impact.Count
	$InformationalCount = $(foreach ($priority in $object.Findings) { $priority | ? { $_.Impact -eq "Informational" } }).Impact.Count
	
	# Misc
	$ReportTitle = "M365SAT - Microsoft 365 Security Audit Tool"
	$ReportSub1 = ""
	$ReportSub2 = "Security Audit Report"
	$ReportSub3 = "This report details any tenant configuration changes recommended within your tenant."
	
	# End of Attributes
	
	# Output start
	$output = "<!doctype html>
    <html lang='en'>
    <head>
        <!-- Required meta tags -->
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>

        <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css' crossorigin='anonymous'>
        <link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'>
        <script src='https://code.jquery.com/jquery-3.3.1.slim.min.js' integrity='sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo' crossorigin='anonymous'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js' integrity='sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1' crossorigin='anonymous'></script>
        <script src='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js' integrity='sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM' crossorigin='anonymous'></script>
        <script src='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/js/all.js'></script>
        
       

        <style>
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
		.m-3 {
			margin: 1rem!important;
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
       
        .table-borderless td,
        .table-borderless th {
            border: 0;
            padding:5px; 

        }
        .bd-callout {
            padding: 1.25rem;
            margin-top: 1.25rem;
            margin-bottom: 1.25rem;
            border: 1px solid #eee;
            border-left-width: .25rem;
            border-radius: .25rem
        }
        
        .bd-callout h4 {
            margin-top: 0;
            margin-bottom: .25rem
        }
        
        .bd-callout p:last-child {
            margin-bottom: 0
        }
        
        .bd-callout code {
            border-radius: .25rem
        }
        
        .bd-callout+.bd-callout {
            margin-top: -.25rem
        }
        
        .bd-callout-info {
            border-left-color: #5bc0de
        }
        
        .bd-callout-info h4 {
            color: #5bc0de
        }
        
        .bd-callout-warning {
            border-left-color: #f0ad4e
        }
        
        .bd-callout-warning h4 {
            color: #f0ad4e
        }
        
        .bd-callout-danger {
            border-left-color: #d9534f
        }
        .bd-callout-critical {
            border-left-color: #660000
        }
        .bd-callout-critical h4 {
            color: #660000
        }
        .bd-callout-danger h4 {
            color: #d9534f
        }
        .bd-callout-success {
            border-left-color: #00bd19
        }
        .bg-critical{
            background-color: #660000
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
        </style>

        <title>$($ReportTitle)</title>

    </head>
    <body class='app bg-light'>

        <nav class='navbar navbar-custom' >
            <div class='container-fluid'>
                <div class='col-sm' style='text-align:left'>
                    <div class='row'><div><i class='fa-solid fa-magnifying-glass'></i></div><div class='ml-3'><strong>$($ReportTitle)</strong></div></div>
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
							<div><h5>Completed at: $($StartDate)</h5></div>"
	
	$Output += "<strong>Version $version </strong>
                            <p> M365SAT assesses your compliance posture, highlights risks and recommends remediation steps to ensure compliance with essential data protection and regulatory standards.</p>"
	
	$Output += "<table><tr><td>
                            <strong>Date</strong>  </td>
                            <td><strong>: $($ReportDate)</strong>  </td>
                            </tr>
                           
                            "
	$output += " <tr><td><strong>Organization &nbsp;</strong> </td>
                                             <td><strong>: $($Tenant)</strong> </td></tr>
                                             "
	$output += " <tr><td><strong>Tenant &nbsp;</strong> </td>
                             <td><strong>: $($TenantDomain)</strong> </td></tr>
                             "
	# There is a bug here that needs to be resolved where the incorrect value is displayed at executed inspector modules
	$output += " <tr><td><strong>Stats &nbsp;</td></strong>
                             <td><strong>: $AffectedObjects</strong> out of <strong>$($inspectors.Count)</strong> executed inspector modules identified possible opportunities for improvement.</td></tr>
                             "
	
	$output += "  </table>"
	
	
	$Output += "<br/>"
	
	<#

        OUTPUT GENERATION / Summary cards

    #>
	
	$Output += "

                <div class='row p-3'>"
	
	$Output += "
                    
                            <div class='col d-flex justify-content-center text-center'>
                                <div class='card card-prio-info mb-3' style='width: 18em;'>
                                    <div class='summary-header'><h6>Informational</h6></div>
                                    <div class='card-body'>
                                    <h3>$($InformationalCount)</h3>
                                    </div>
                                </div>
                            </div>
                    
                    "
	
	$Output += "<div class='col d-flex justify-content-center text-center'>
                    <div class='card card-prio-low mb-3' style='width: 18rem;'>
                        <div class='summary-header'><h6>Low</h6></div>
                        <div class='card-body'>
                        <h3>$($LowCount)</h3>
                        </div>
                    </div>
                </div>

                <div class='col d-flex justify-content-center text-center'>
                    <div class='card card-prio-medium mb-3' style='width: 18rem;'>
                        <div class='summary-header'><h6>Medium</h6></div>
                        <div class='card-body'>
                        <h3>$($MediumCount)</h3>
                        </div>
                    </div>
                </div>"
	
	$Output += "<div class='col d-flex justify-content-center text-center'>
                    <div class='card card-prio-high mb-3' style='width: 18rem;'>
                        <div class='summary-header'><h6>High</h6></div>
                        <div class='card-body'>
                        <h3>$($HighCount)</h3>
                        </div>
                    </div>
                </div>

                <div class='col d-flex justify-content-center text-center'>
                    <div class='card card-prio-critical mb-3' style='width: 18rem;'>
                        <div class='summary-header'><h6>Critical</h6></div>
                        <div class='card-body'>
                        <h3>$($CriticalCount)</h3>
                        </div>
                    </div>
                </div>
            </div>"
	
    <#
    
                OUTPUT GENERATION / Config Health Index

    #>
	
	$Output += "
    <div class='card m-3'>

        <div class='card-body'>
            <div class='row'>
                <div class='col-sm-4 text-center align-self-center'>

                    <div class='progress' style='height: 40px'>
                        <div class='progress-bar progress-bar-striped bg-info' role='progressbar' style='width: $(($object.Findings.Count/$inspectors.Count) * 100)%;' aria-valuenow='$(($object.Findings.Count/$inspectors.Count) * 100)' aria-valuemin='0' aria-valuemax='100'><h2>$(($object.Findings.Count/$inspectors.Count) * 100) %</h2></div>
                    </div>
                
                </div>
                <div class='col-sm-8'>
                    <h6>Configuration Health Index</h6>                  
                    <p>The configuration health index is a weighted value representing your configuration. Not all configuration is 
                    considered the same. Some configuration is weighted higher than others.<a href='https://aka.ms/m365sat-github' target='_blank'> See More </a></p>

                </div>
            </div>

            <div class='alert alert-success pt-2' >
            Like this report? Try similar reporting for Microsoft's Compliance solutions. Download <a href='https://aka.ms/orca-mcca-github' target='_blank'> Microsoft Compliance Config Analyzer (MCCA)</a>
             </div>
                    
    </div>
  
    
    "
	
	
	
        <#
    
        OUTPUT GENERATION / Summary

    #>
	
	$Output += "
    <div class='card m-3'>
    <a name='Solutionsummary'></a>

        <div class='card-header'>
          Solutions Summary
        </div>
        <div class='card-body'>"
	$Output += "<table class='table table-borderless'>
        <tr>
            <td width='20'><i class='fa-solid fa-check'></i>
            <td><strong>All Solutions</strong></td>
            <td align='right'>
                <span class='badge card-prio-info' style='padding:15px;text-align:center;width:40px;"; $output += "'>$($InformationalCount)</span>
                <span class='badge card-prio-low' style='padding:15px;text-align:center;width:40px;"; $output += "'>$($LowCount)</span>
                <span class='badge card-prio-medium' style='padding:15px;text-align:center;width:40px;"; $output += "'>$($MediumCount)</span>
				<span class='badge card-prio-high' style='padding:15px;text-align:center;width:40px;"; $output += "'>$($HighCount)</span>
				<span class='badge card-prio-critical' style='padding:15px;text-align:center;width:40px;"; $output += "'>$($CriticalCount)</span>
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
			if ($Prod.Impact -eq "Critical")
			{
				$Critical++
			}
			elseif ($Prod.Impact -eq "High")
			{
				$High++
			}
			elseif ($Prod.Impact -eq "Medium")
			{
				$Medium++
			}
			elseif ($Prod.Impact -eq "Low")
			{
				$Low++
			}
			elseif ($Prod.Impact -eq "Informational")
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
                <td style='vertical-align:middle;'>&nbsp;&nbsp;<img src='$($Icons[$i])' style='width: 16px; height: 16px' title='$($Productfamily)'>&nbsp;&nbsp; <a href='`#$($Productfamily.Replace(" ", "_"))'>$($Productfamily)</a></td>
                <td align='right' style='vertical-align:middle;'>
                <span class='badge card-prio-info' style='padding:10px;text-align:center;width:30px;";
		$output += "'>$($Info)</span>
                <span class='badge card-prio-low' style='padding:10px;text-align:center;width:30px;";
		$output += "'>$($Low)</span>
                <span class='badge text-white card-prio-medium' style='padding:10px;text-align:center;width:30px;";
		$output += "'>$($Medium)</span>
                <span class='badge card-prio-high' style='padding:10px;text-align:center;width:30px;";
		$output += "'>$($High)</span>
                <span class='badge text-white card-prio-critical' style='padding:10px;text-align:center;width:30px;";
		$output += "'>$($Critical)</span>
                </td>
            </tr>
            "
		$i++
	}
	
	#Legenda Information
	$Output += "
    <tr><td colspan='3' style='text-align:right'> 
        <span class='badge card-prio-info'style='padding:5px;text-align:center'> </span>&nbsp;Informational
        <span class='badge card-prio-low'style='padding:5px;text-align:center'> </span>&nbsp;Low
        <span class='badge card-prio-medium' style='padding:5px;text-align:center'> </span>&nbsp;Medium
        <span class='badge card-prio-high' style='padding:5px;text-align:center'> </span>&nbsp;High
        <span class='badge card-prio-critical' style='padding:5px;text-align:center'> </span>&nbsp;Critical
    </td></tr></table>"
	$Output += "
        </div>
    </div>
    "
	
        <#

        OUTPUT GENERATION / Zones

    #>
	
	#Put here list of Inspector Modules Executed:
	$CollapseId = "Executed_Inspectors"
	$Output += "<a name='Executed Inspectors'></a> 
        <div class='card m-3'>
            <div class='card-header'>
            <div class=""row"">
            <div class='col-sm' style='text-align:left; margin-top:auto; margin-bottom:auto;'><a>Executed Inspectors</a></div>
            <div class='col-sm' style='text-align:right; padding-right:10px;'> 
            <span id='more_$($CollapseId)' data-toggle='collapse' data-target='#$($CollapseId)_body'>
            <i class='fas fa-chevron-down' >&nbsp;&nbsp;</i>
            </span>
            </div>  
            </div>        
            </div>"
	
	$Output += "<div class='card-body collapse show' id='$($CollapseId)_body'>"
	
	ForEach ($Inspector in $inspectors)
	{
		$Output += "<div class='col-sm-10' style='text-align:left; margin-top:auto; margin-bottom:auto;'>$($Inspector)</div>"
	}
	
	$Output += "</div></div>"
	
	ForEach ($Productfamily in $ProductFamilies)
	{
		$Products = $(foreach ($Product in $object.Findings) { $Product | ? { $_.ProductFamily -eq $Productfamily } }) | Sort-Object -Property CVS
		$CollapseId = $($Productfamily).Replace(" ", "_")
		$Output += "<a name='$($Productfamily)'></a> 
        <div class='card m-3'>
            <div class='card-header'>
            <div class=""row"">
            <div class='col-sm' style='text-align:left; margin-top:auto; margin-bottom:auto;'><a>$($Productfamily)</a></div>
            <div class='col-sm' style='text-align:right; padding-right:10px;'> 
            <span id='more_$($CollapseId)' data-toggle='collapse' data-target='#$($CollapseId)_body'>
            <i class='fas fa-chevron-down' >&nbsp;&nbsp;</i>
            </span>
            </div>  
            </div>        
            </div>
            
            <div class='card-body collapse show' id='$($CollapseId)_body'>"
		$i = 0
		
		ForEach ($Result in $Products)
		{
			$RemediationActionsExist = $false
			$CheckCollapseId = $($Productfamily).Replace(" ", "_") + $i.ToString()
			# Validation if result corresponds with severity
			If ($Result.Impact -eq "Informational")
			{
				$CalloutType = "bd-callout-info"
				$BadgeType = "card-prio-info"
				$BadgeName = "Informational"
				$Icon = "fas fa-thumbs-up"
				$IconColor = "#2986CC"
				$Title = $Check.PassText
			}
			ElseIf ($Result.Impact -eq "Low")
			{
				$CalloutType = "bd-callout-success"
				$BadgeType = "card-prio-low"
				$BadgeName = "Low"
				$Icon = "fas fa-thumbs-up"
				$IconColor = "#38761D"
				$Title = $Check.PassText
			}
			ElseIf ($Result.Impact -eq "Medium")
			{
				$CalloutType = "bd-callout-warning"
				$BadgeType = "card-prio-medium"
				$BadgeName = "Medium"
				$Icon = "fas fa-thumbs-down"
				$IconColor = "#FFC107"
				$Title = $Check.FailRecommendation
			}
			ElseIf ($Result.Impact -eq "High")
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
                    <div class='row border-bottom' style='padding:5px; vertical-align:middle;'>
                    <div class='col-sm-10' style='text-align:left; margin-top:auto; margin-bottom:auto;'><h6>[$($Result.CVS)]: $($Result.FindingName)</h6></div>
                    <div class='col' style='text-align:right;padding-right:10px;'> 
                    <h6>
                    <span class='badge $($BadgeType)'>$($BadgeName)</span>&nbsp;&nbsp;
                    <i class='fas fa-chevron-down' data-toggle='collapse' data-target='#$($CheckCollapseId)'></i>
                    </h6>
                    </div>  
                    </div>"
			#Start of Container Generation Within group object (FindingName)
			$Output += "  
                    <div class='row collapse' id='$($CheckCollapseId)'>
                        <div class='bd-callout $($CalloutType) b-t-1 b-r-1 b-b-1 p-3' >
                            <div class='container-fluid'>
                                <div class='row'>
                                    <div><i class='$($Icon)' color='$($IconColor)'></i></div>
                                    <div class='col-8'><h6>$($Result.FindingName)</h6></div>
                                   
                                </div>"
			$i++
			#Display Description below 
			# Result.ID is a test. If the output is messed up, please remove!
			$Output += "
					   <div><b>ID:$($Result.ID)</b></div>
                       <div class='row p-3'>
                            <div><b>Description:</b><p>$($Result.Description)</p></div>

                                </div>"
			
			# Remediation Explanation
			$output += "<div class='row p-3'>
                            <div><b>Remediation:</b><p>$($Result.Remediation)</p></div>

                    </div>"
			
			# PowerShellScript
			$output += "<div class='row p-3'>
                            <div><b>PowerShell Script:</b><p>$($Result.PowershellScript)</p></div>

                                </div>"
			
			#Table information that should contain default value, expected value, returned value
			# We should expand the results by showing a table of Config Data and Items
			$Output += "
                            <div class='row pl-2 pt-3'>"
			
			$Output += "  <table class='table'>
                                    <thead class='border-bottom'>
                                        <tr>"
			
			# Object, property, value checks need three columns (Table Headers)
			$Output += "
                            <th align='center' text-align='center'>Returned Value</th>
                            <th align='center' text-align='center'>Default Value</th>
                            <th align='center' text-align='center'>Expected Value</th>
                            <th align='center' text-align='center'>Impact</th>
                           "
			$Output += "
                            <th style='width:50px'></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                            "
			
			
			# Table Body Fill (put info of Default,Expected and Current value here below!!!)
			
			$Output += "
                                <tr>
                                "
			#Checks if remedation is possible (returning value from object
			
			if ($Result.ReturnedValue.Count -GT 10)
			{
				$Output += "
                                    <td><a href='$($Result.FindingName).txt'>$($Result.ReturnedValue.Count) Affected Objects Identified<a/>.
                                    <td style='word-wrap:break-word;' width = '35%'>$($Result.DefaultValue)</td>
                                    <td style='word-wrap:break-word;' width = '30%'>$($Result.ExpectedValue)</td>

                                    "
				$fname = $Result.FindingName
				$Result.ReturnedValue | Out-File -FilePath $OutputDir\$fname.txt
			}
			else
			{
				$Output += "
                                <td>"
				ForEach ($Values in $Result.ReturnedValue)
				{
					$Output += "$($Values)</br>"
				}
				$Output += "</td>
                                <td style='word-wrap:break-word;' width = '35%'>$($Result.DefaultValue)</td>
                                <td style='word-wrap:break-word;' width = '30%'>$($Result.ExpectedValue)</td>
                                "
			}
			
			# Last Row (Status)
			$Output += "
                                    <td style='text-align:left'>
                                        <div class='row badge badge-pill badge-light'>"
			$Output += "<span style='vertical-align: left;'>$($Result.Impact)</span><br/></div>"
			
			
			$Output += " 
                                    </td>
                                </tr>
                                "
			
			# Recommendation segment
			if (($null -ne $($Result.InfoText)) -and ($($Result.InfoText) -ne ""))
			{
				
				$Output += "
                                    <tr>"
				If ($Check.CheckType -eq [CheckType]::ObjectPropertyValue)
				{
					$Output += "<td colspan='4' style='border: 0;'>"
				}
				
				
				$Output += "
                                    <div class='alert alert-light' role='alert' style='text-align: left;'>
                                    <span class='fas fa-info-circle text-muted' style='vertical-align: left; padding-right:5px'></span>
                                    <span style='vertical-align: middle;'>$($Result.InfoText)</span>
                                    </div>
                                    "
				
				$Output += "</td></tr>
                                    
                                    "
			}
			
			$Output += "
                                    </tbody>
                                </table>"
			
			
			$Output += "<span style='vertical-align: left;'>References:</span><br>"
			
			# Last line for the References to put there
			
			$Output += "
                                <table class='table'>"
			Foreach ($Reference in $Result.References)
			{
				$Output += "
                                    <tr><td style='padding-top:20px;'><i class='fas fa-external-link-square-alt'></i>&nbsp;<a href='$($Reference.URL)' target=""blank"">$($Reference.Name)</a></td></tr>"
			}
			
			$Output += "
                            
                                    <td><a class='btn btn-primary' href='$($RemediationReportFileName)' target='_blank' role='button'>Remediation Script</a></td>"
			$Output += "
                            </table>
                            "
			$Output += "
                            </table>
                            "
			
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
                      

        </div>"
	}
	
        <#

        OUTPUT GENERATION / Footer

    #>
	
	$Output += "
            </main>
            <center>Bugs? Issues? Suggestions? <a href='https://github.com/karmakstylez/M365SAT'>GitHub</a></center>
            </div>
            <footer class='app-footer'>
            <p><center><i>&nbsp;&nbsp;&nbsp;&nbsp;Disclaimer: Recommendations from (M365SAT) should not be interpreted as a guarantee of compliance. It is up to you to evaluate and validate the effectiveness of customer controls per your regulatory environment. </br>
               </i></center> </p></footer>
        </body>
    </html>"
	
	
	# Write to file
	
	# Create a new directory for the new report
	$OutPath = New-CreateDirectory($OutPath)
	
	#Assign specific value to html report
	$ReportFileName = "M365SAT-$(Get-Date -Format 'yyyyMMddHHmm').html"
	
	$OutputFile = "$OutPath\$ReportFileName"
	
	$Output | Out-File -FilePath $OutputFile
	
	#Create a .zip File of the full report including the objects
	New-ZipFile($OutPath)
	
	# Open the HTML Report
	Invoke-Expression $OutputFile
	
}

function New-ZipFile($outpath)
{
	try
	{
		$compress = @{
			Path			 = $OutPath
			CompressionLevel = "Fastest"
			DestinationPath  = "$OutPath\$($Tenant)_Report_$(Get-Date -Format "yyyy-MM-dd_hh-mm-ss").zip"
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
			$newpath = "$OutPath\$($Tenant)_$(Get-Date -Format "yyyyMMddhhmmss")"
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
			$newpath = "$OutPath\$($Tenant)_$(Get-Date -Format "yyyyMMddhhmmss")"
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