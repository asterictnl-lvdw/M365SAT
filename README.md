# M365SAT
## The Official Microsoft 365 Security Assessment Tool
Written in PowerShell 7 and 5.1

Current Version: v2.3

Next Scheduled Release: Q1 (January 2025)

Next Release Version: v3.0

<div>
  <p align="center">
    <b>The Open-Source, Automated Microsoft 365 Security Assessment Tool</b> </br></br>
    <img src=x width="800"> 
  </p>
</div>


[![OS](https://img.shields.io/badge/OS-Windows-blue?style=flat&logo=Windows)](https://www.microsoft.com/en-gb/windows/?r=1)
[![Docker](https://img.shields.io/badge/Docker-Coming_Soon-red.svg?style=flat&logo=docker)](https://github.com/asterictnl-lvdw/365Inspect)


## 1. Intro

Almost 50% of the people around the world use Microsoft 365 as their solution to do office work. 

We are aware of these growing problems and therefore has a unique technical solution to offer. Thanks to knowledge including Microsoft 365 security, We can take a step further into auditing even more Microsoft 365 Environments than any other security suite. To achieve this we have released our new solution for Microsoft 365 and Azure environments called M365SAT.

M365SAT protects your organization's Microsoft 365 tenant, by identifying misconfigurations and helping to mitigate areas of risk.

Elevate your Microsoft 365 environment to unprecedented levels of security with our comprehensive solution. Perfectly crafted to safeguard your digital assets, this solution offers unparalleled protection against evolving cyber threats, ensuring peace of mind for your Microsoft 365 environment.

Our solution goes beyond conventional security measures by meticulously examining around 300 distinct settings across the entire Microsoft 365 suite. From Teams to Exchange, SharePoint to Azure, every facet of your ecosystem is scrutinized to identify and neutralize potential vulnerabilities. With this exhaustive inspection, you can rest assured that no stone is left unturned in fortifying your digital fortress.

By thoroughly examining your Microsoft 365 Cloud settings, the tool identifies any deviations from the recommended CIS Benchmark configurations. This enables your organization to quickly address potential security vulnerabilities and comply with industry best practices. Our solution is not limited to just signaling problems; it goes a step further by providing remediation guidance in the form of PowerShell scripts. This invaluable feature simplifies the remediation process, saving your IT team valuable time and effort.

## 2. About M365SAT
M365SAT is an evolution of it's predecessor called 365Inspect+ released in 2022. The goal of M365SAT is to allow Security and Compliance Administrators to easily meassure their environment's posture. 

Our tool is completely free and open source. It works with PowerShell for assessing Microsoft 365 and Azure security configurations. With around 300 points of inspection, it assists administrators in reducing risky configurations.

The core features of M365SAT are as followed:
- Automated-Scanning: *It allows the administrator to just fire and forget by logging in several times to start the scanning process*
- Detailed-Reporting: *A detailed HTML-Report is generated including the risk, rationale
- Modularity: *It allows the creation of new scan modules to enhance your auditing mechanism. Instructions on how to develop such module can be found in the Examples Section.*


## 3. Installation
M365SAT can be installed the following ways:

-	Install-Module M365SAT (Coming in the next release!)
-	By Downloading the latest release and using Import-Module on the psd1 file
-	By Downloading the latest release and using the M365SATTester.ps1 file

### 3.1 Modules Installation

The following modules need to be installed in order to make M365SAT work:
-	Az
-	ExchangeOnlineManagement
-	Microsoft.Online.SharePoint.PowerShell
-	Microsoft.Graph
-	MicrosoftTeams
-	PoShLog

#### 3.1.1 Installation PowerShell 7.x.x (Windows)
PowerShell 7.x works with all the latest modules.
```
Install-Module -Name Az
Install-Module -Name ExchangeOnlineManagement
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```

#### 3.1.2 Installation PowerShell 5.1 (Windows)
Note: *Microsoft PowerShell 5.1 does not work properly with Az.Accounts 3.x.x or later, due to the new mechanism of authentication it conflicts with the ExchangeOnlineManagement modules. 2.19.0 is the latest working version with PowerShell 5.1.*
```
Install-Module -Name Az
Install-Module -Name ExchangeOnlineManagement -AllowClobber -Force
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```
1. Remove from here the `3.x.x` folder `C:\Program Files\WindowsPowerShell\Modules\Az.Accounts`
2. Run `Install-Module -Name Az.Accounts -RequiredVersion 2.19.0` to install the working PowerShell 5.1 version.

#### 3.1.3 Installation PowerShell 7.x.x (Linux)
*Note: This only works starting from v3.0!!!*
PowerShell 7 works with Linux, the only module that is not working straightforward is Microsoft Sharepoint. Thus will be replaced with PnP when using a Linux environment. For Linux you must follow the instructions below:
1. Run `sudo pwsh`
2. In the PowerShell SuperUser session run: `Install-Module -Name PSWSMan`
3. After installation run the command: `Install-WSMan`
4. You will be prompted to restart the PowerShell Session. Close the SuperUser session
5. Install all the modules down below:
```
Install-Module -Name Az
Install-Module -Name ExchangeOnlineManagement -AllowClobber -Force
Install-Module -Name PnP.PowerShell
Install-Module -Name Microsoft.Graph -AllowClobber -Force
Install-Module -Name Microsoft.Graph.Beta -AllowClobber -Force
Install-Module -Name MicrosoftTeams
Install-Module -Name PoShLog
```
Please keep in mind that there might be things that are not working. Feel free to report any bugs if found.!

### 3.2 Method 1: Install-Module
This method is coming in the next major release

## 4. How-To-Use
M365SAT is very easy to use. There are two main ways of executing M365SAT:

1. Using the M365SATTester.ps1 script
2. Executing Get-M365SATReport after importing the M365SAT modules

### 4.1 Necessary Privileges to Run
M365SAT compared to its predecessor it needs less permissions than 365Inspect+. The following permissions can be used to run a successful audit:

-	Application Administrator
-	SharePoint Administrator
-	Exchange Administrator
-	Global Reader

These permissions are tested with the latest M365SAT version and reported to be working as for 20-7-2023

Although it is not necesary anymore to use Global-Administrator, we do recommend using an account with Global Administrator for the best results.

Why do we need SharePoint Administrator and can't we use lesser permissions? The problem some settings can only be read when you are Administrator. Source: https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-reader

### 4.1 Method 2: Running M365SATTester.ps1 (Recommended)
Make sure you RUN PowerShell as Administrator.
1. Clone the github repository or download the latest release at the releases section
2. cd C:\M365SAT; Get-ChildItem -Path .\ -Recurse | Unblock-File to unblock all files
3. Edit the M365SATTester.ps1 and replace -Username value with the username containing at least Global Reader and SharePoint Admin permissions.
4. Run M365SATTester.ps1 as Administrator the M365SAT.psm1 will be automatically imported and the assessment will be started!

### 4.2 Method 3: Import-Module M365SAT.psd1
Only use this method if you already installed all additional modules. Else step 5 will return a lot of errors! Use method 4 to install the required modules and return to this.
1. Clone the github repository or download the latest release at the releases section
2. cd C:\M365SAT; Get-ChildItem -Path .\ -Recurse | Unblock-File
3. Import-Module .\M365SAT.psd1
4. Wait until the process is finished, there might be some errors, because of not implemented solutions, you can safely ignore them.
5. See 5.2 for the execution command

### 4.3 Execution Commands
The execution of M365SAT can be done as followed:
```
Get-M365SATReport -OutPath <value> -reportType <HTML/CSV/XML> -Username <username> (-Password <password> -SkipChecks -SkipLogin -UseCustomModules -AllowLogging <Verbose/Debug/Info/Warning/Error/Fatal> -Modules <All/MicrosoftAzure/MicrosoftExchange/MicrosoftOffice365/MicrosoftSharepoint/MicrosoftTeams> )
```

#### 4.3.1 Mandatory Parameters

`-OutPath`: Specifies the output path for the exported report.

`-Username`: Mandatory. Enter the administrator username.

`-EnvironmentType`: Mandatory. Choose the environment to audit. Options include:

- M365: Microsoft 365
- AZURE: Azure
- CUSTOM: Custom Scripts in the /CUSTOM folder
- ALL: All environments

`-BenchmarkVersion`: Choose the benchmark version. Options include:

- 3: Benchmark version 3
- 2: Benchmark version 2
- LATEST: Latest available benchmark version

`-Modules`: Choose the modules to audit. Options include:

- Azure: Azure
- Exchange: Exchange
- Office365: Office 365
- Sharepoint: SharePoint
- Teams: Teams
- All: All modules

`-reportType`: Choose the report format. Options include:
- HTML: HTML
- CSV: CSV
- XML: XML
- CSMS: CSMS

Note: Only HTML fully works at the moment!

#### 4.3.2 Optional Parameters

`-Environment`: Specifies the environment type. Options include:

- Default: Standard environment
- USGovGCCHigh: U.S. Government Cloud Computing High
- USGovDoD: U.S. Government Department of Defense
- Germany: Germany region
- China: China region

`-Password`: Enter the administrator password. (Non-MFA Account)

`-LicenseMode`: Choose the benchmark license mode. Options include:

- E3: E3 license
- E5: E5 license
- All: All license modes

`-LicenseLevel`: Choose the benchmark level. Options include:

- L1: Level 1
- L2: Level 2
- All: All levels

`-AllowLogging`: Specifies the log message level. Options include:

- Verbose: Verbose logging
- Debug: Debug logging
- Info: Informational logging
- Warning: Warning logging
- Error: Error logging
- Fatal: Fatal logging

`-SkipChecks`: Skips module updates (experimental).

`-ExpirimentalMode`: Uses the experimental multi-threaded scanner (not recommended).

`-LocalMode`: Enables using the /inspectors folder instead of downloading the inspectors from GitHub.

`-SkipLogin`: Skips login if already authenticated (Not-Recommended).


### 4.4 Execution Examples
In normal situations when using the standard command to execute a security assessment you will be prompted with graphical login screens where you must sequentially log into. 

.\M365SATTester.ps1

You can simply add the desired parameters to this script and run it from here.

Depending on the capacity of the organization, M365SAT may take some time to execute. For organizations with a tiny amount of user accounts and none to little configuration M365SAT will not take longer than 30 minutes. For organizations that have more than 100 accounts and more custom configurations it would take longer. It all depends on how large and complex the organization is and how much is configured. 

## 5. Development
Unlike 365Inspect+, M365SAT is far more modular than its predecessor. Besides the design to expand easily additional modules can now be easily expanded or troubleshooted when occuring problems. We have divided muliple modules into directories so when an user builds a new module they can easily create a new directory and develop the new module. 

### 5.1 Developing Inspector Modules
All Inspector modules are stored in the .\inspectors folder. You can use any earlier created module as a template to create a new module. Most of the modules are called:

*CSTM-[ProductFamily][ID].ps1*

For ProductFamily we have the following options at the moment:
-	Az (Microsoft Azure)
-	Ex (Microsoft Exchange)
-	O365 (Microsoft 365)
-	Sp (Microsoft Sharepoint)
-	Tms (Microsoft Teams)

ID Should be XXX-format e.g. 001, 002, 003, etc.

#### 5.1.1 Example
The following example is a Sharepoint Custom Inspector:

````
# Date: 6-5-2024
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Sharepoint
# Purpose: Ensure Idle Browser SignOut is correctly configured
# Author: REDACTED

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Sp001($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Sp001"
		FindingName	     = "CSTM-Sp001 - Sharepoint has no Idle Browser SignOut Configuration Configured"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "9.1"
		Description	     = "Idle session timeout in SharePoint Online is a security mechanism that warns and sign-outs the user after a period of inactivity. By default, idle session timeout settings are disabled in SharePoint Online. Not enabling leaves the user at risk for step-by attacks."
		Remediation	     = "Execute the following command to enable Idle Session Timeout= <b>  </b>"
		DefaultValue	 = @("Enabled= False", "WarnAfter= 0", "SignOutAfter= 0")
		ExpectedValue    = @("Enabled= True", "WarnAfter= 30", "SignOutAfter 60")
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOBrowserIdleSignOut -Enabled $true -WarnAfter (New-TimeSpan -Minutes 30) -SignOutAfter (New-TimeSpan -Minutes 60)'
		References	     = @(@{ 'Name' = 'Enforcing idle session timeout restrictions in SharePoint Online'; 'URL' = 'https://www.michev.info/Blog/Post/1857/enforcing-idle-session-timeout-restrictions-in-sharepoint-online' })
	}
}


function Audit-CSTM-Sp001
{
	try
	{
		$command = Get-SPOBrowserIdleSignOut | Select-Object Enabled
		if ($command.Enabled -eq $false)
		{
			$command | Format-Table -AutoSize | Out-File "$path\CSTM-Sp001.txt"
			$endobject = Build-CSTM-Sp001("SPOBrowserIdleSignOut: $($command.Enabled)")
			return $endobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Sp001
````

To briefly explain the parts above:
-	1, Description of your program, including author, purpose, etc.
-	2, you have the error handling with PoShLog
-	3, optionally if your script has logs to export you can use the *$path = @($OutPath)* to make sure the logs are being put into the correct folder
-	4, The 'Build' Function containing the information if violation of the inspector is found the Build function can be executed to create a CustomPSObject to return for the report.
-	5, the actual script that checks if there is any violation. You always provide $endobject = Build-{Yourinspectorname}(x) and return $endobject. x is the information you want to pass to the build function to fill the PSCustomObject with so the findings can be reported back into the report

Some Coding Tips:
 -	Use try & catch in case if your inspector has problems the output will return null or an exception will be thrown. The output those errors can be found in the same directory into an additionally created log directory where the errorlogs are placed.
 -	Try to use as less code as possible. Long strings of code will delay the overall performance and makes the security assessment much longer than usual
 -	If you really want to make beautiful well-formatted PowerShell Inspectors. Take a look at SAPIEN PowerShell Studio. It has a nice Format-Script function that allows you to very much format the script into readable parts to save you time finding issues if there are any.

### 5.2 Developing Additional Modules
You can develop additional modules and place them either in the .\modules if it is a pre-check module or in the core module if it is an addition to the core of the program. If you develop a new way to output a report into a different file you can place the so-called 'parser' into the .\output folder

## 6. About M35SAT's Security
Me as a Vulnerability Assessor take security very seriously. Take in mind that this program can execute other inspector modules. That means even malicious scripts can be ran if wanted. I am not responsible for any damage or loss of files if that is the case.

Please use the security best-practices as followed:
-	Use least privilege on the account you audit with. So only the necessary privileges for the audit being used on the account you are provided with,
-	Write-Protect the inspector folder for unauthorized access to make sure your inspectors are not being overwritten with malicious code,
-	Do not place, unless it is trusted, any PowerShell script into the inspectors folder

## 7. License
M365SAT is an open-source and free software released under the [MIT License](https://github.com/asterictnl-lvdw/M365SAT/blob/main/LICENSE). All the additional plug-ins and frameworks are also accompanied by the same MIT Licence. 

## 8. Special Thanks To...
* [Soteria-Security](https://github.com/soteria-security/365Inspect): For allowing me to create the fork on the predecessor!
* [AsterICTNL](https://www.asterict.nl): For allowing me to additionally develop this further
* [CISSecurity](https://www.cisecurity.org/cis-benchmarks/): For providing the Azure and Microsoft 365 benchmarks to make the inspector modules
* [cammurray](https://github.com/cammurray/orca): For the reporting structure
* [OfficeDev](https://github.com/OfficeDev/MCCA): For the reporting structure

## 9. Donation
Donations are always welcome! Feel free to Donate to me through PayPal!