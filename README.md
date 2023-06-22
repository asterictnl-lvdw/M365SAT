# M365SAT
## The Official Microsoft 365 Security Assessment Tool
Written in PowerShell 5.x and soon PowerShell 7.x as well!

<div>
  <p align="center">
    <b>The Open-Source, Automated Microsoft 365 Security Assessment Tool</b> </br></br>
    <img src="" width="800"> 
  </p>
</div>

<b>Next Scheduled Release: July 2023</b>

[![OS](https://img.shields.io/badge/OS-Windows-blue?style=flat&logo=Windows)](https://www.microsoft.com/en-gb/windows/?r=1)
[![made-with-powershell](https://img.shields.io/badge/Made%20with-Powershell-1f425f.svg?logo=Powershell)](https://github.com/powershell/powershell)
[![Docker](https://img.shields.io/badge/Docker-Coming_Soon-red.svg?style=flat&logo=docker)](https://github.com/asterictnl-lvdw/365Inspect)
[![Maintenance](https://img.shields.io/badge/Maintained-yes-green.svg)](https://github.com/asterictnl-lvdw/M365SAT)
[![GitHub](https://img.shields.io/github/license/asterictnl-lvdw/M365SAT)](https://github.com/asterictnl-lvdw/M365SAT/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/Documentation-complete-green.svg?style=flat)](https://github.com/asterictnl-lvdw/M365SAT/)

## 2. Purpose

M365SAT is used to meassure the strength of your Microsoft 365 and Microsoft Azure environment. This includes Microsoft Office 365, Microsoft Teams, Microsoft SharePoint, Microsoft Exchange and Microsoft Azure. Besides that M365SAT can also check if your tenant is compliant by using the CIS Benchmarks.

## 3. About M365SAT

M365SAT is a sequel to the previously released "365Inspect+" program. M365SAT is a command-line utility tool that can be used to easily assess not only Microsoft 365, but also Azure subscriptions and Azure Active Directory security configuration without the difficulties of learning how to use an API or complex admin panels from the start. 

M365SAT has been designed to allow an administrator to easily assess and get results fast without the need of additional tools. M365SAT retrieves configuration information from your instance and validates whether or not a series of security best practices have been followed and if your instance is compliant against the CIS benchmark or not. M365SAT can output the following: A beautiful HTML report, a .CSV file, JSON-file and in the future even more output solutions will be implemented. These reports provide descriptions of any discovered security flaws as well as actionable recommendations you can use to improve the security state of your instance.

M365SAT is open-source and completely free of charge! All you need is to import the module as Administrator and install the required modules to do the security assessment.

M365SAT works in five phases. In the first phase you are prompted to login at the modules that are needed to do the security assessment, this is the only phase that might need manual action if your account has MFA configured. In the second phase the so-called 'inspectors' are selected and prepared for the third phase. In the third phase the actual audit takes place and every inspector of admin's choice is executed. The inspectors contain sets of rules, as a mechanism to evaluate the configuration of the instance chosen to audit and to search for potential misconfigurations and security issues within the instance. The console gives a summary of what inspectors found something and what inspectors didn't. In the fourth phase the information that is gathered is processed in the report to generate to review the condition of your instance. In the fifth phase the program simply disconnects the modules so no abuse could be done afterwards and leftoverfiles are cleaned up.

In continuation, M365SAT is modular. It allows developers to develop new scan modules to enhance your audit mechanism. Instructions on how to develop such module can be found in the Examples Section.

## 4. Installation
M365SAT can be installed the following ways:

- Install-Module M365SAT (Coming Soon!)
- By Downloading the latest release and using Import-Module on the psd1 file
- By Downloading the latest release and using the M365SATTester.ps1 file
- The manual way!

But first you have to make sure you install either the required modules manually or via de Import-Module script.

### 4.1 Additional Modules Installation

The following modules need to be installed:
- MSOnline
- AzureADPreview
- Az
- ExchangeOnlineManagement
- Microsoft.Online.SharePoint.PowerShell
- Microsoft.Graph
- PnPPowerShell
- MicrosoftTeams
- Microsoft.Graph.InTune

	Install-Module -Name MSOnline
	Install-Module -Name AzureADPreview
	Install-Module -Name Az
	Install-Module -Name ExchangeOnlineManagement
	Install-Module -Name Microsoft.Online.SharePoint.PowerShell
	Install-Module -Name Microsoft.Graph
 	Install-Module -Name PnP.PowerShell
	Install-Module -Name MicrosoftTeams
	Install-Module -Name Microsoft.Graph.Intune

### 4.2 Method 1: Install-Module
This method is coming in future releases

### 4.3 Method 2: Import-Module M365SAT.psd1
Make sure you RUN PowerShell as Administrator. Else the Import-Module does not work properly!
1. Clone the github repository or download the latest release at the releases section
2. cd C:\M365SAT; Get-ChildItem -Path .\ -Recurse | Unblock-File
3. Import-Module .\M365SAT.psd1
4. Wait until the process is finished, there might be some errors, because of not implemented solutions, you can safely ignore them.
5. Run Get-M365SATReport -OrgName "Contoso" -OutPath "C:\out" -Username "example@contoso.org" -reportType HTML -SkipChecks -UseCustomModules and replace the Username with the username containing the Global Reader and SharePoint Admin permissions and use the OrgName that is used on the SharePoint.

### 4.4 Method 3: Import-Module M365SAT.psm1
Only use this method if you already installed all additional modules. Else step 5 will return a lot of errors! Use method 4 to install the required modules and return to this.
1. Clone the github repository or download the latest release at the releases section
2. cd C:\M365SAT; Get-ChildItem -Path .\ -Recurse | Unblock-File
3. Edit the M365SATTester.ps1 and replace the -OrgName value with the Sharepoint tenant name and -Username value with the username containing the Global Reader and SharePoint Admin permissions.
4. Run M365SATTester.ps1 as Administrator the M365SAT.psm1 will be automatically imported and the audit will be started!

## 5. How-To-Use
M365SAT is very easy to use. There are two main ways of executing M365SAT:

1. Using the M365SATTester.ps1 script
2. Executing Get-M365SATReport after importing the M365SAT modules

### 5.1 Necessary Privileges to Run
M365SAT compared to its predecessor it needs less permissions than 365Inspect+. It is not necesary anymore to use Global-Administrator. The following permissions can be used to run a successful audit:

- Local Administrator on your own computer to run PowerShell scripts as Admin
- Global Reader
- SharePoint Administrator

Why do we need SharePoint Administrator and can't we use lesser permissions? The problem some settings can only be read when you are Administrator. Source: https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-reader

### 5.2 Execution Commands
The execution of M365SAT can be done as followed:
Get-M365SATReport -OrgName <value> -OutPath <value> -reportType <HTML/CSV/XML> (-Username <username> -Password <password> -SkipUpdateCheck -UseCustomModules -SelectedInspectors @(array) -ExcludedInspectors @(array) *these are optional*)

The following Parameters are Required:
-OrgName : This is the name of the SharePoint environment,
-OutPath : This is the location where the logs and report will be saved in
-reportType : This is the output-type of the report. You can choose between HTML, JSON and CSV

The following Parameters are Optional:
*-Username* : The username that contains the global reader and sharepoint administrator permissions. If you fill only the Username it speeds up the process of logging in into modules
*-Password* : The password of the account containing the global reader and sharepoint administrator permissions. Please note that this does not work if an account has MFA permissions. If that is the case, use either -Username only or leave exclude these two parameters
*-SkipChecks* : Skips the pre-checks such as program updates, module updates, duplicate checks and module existence
*-UseCustomModules* : Uses modules that are locally stored in the .\inspectors folder instead of gathering them from GitHub. (For versions earlier than 1.1 this parameter is required, else no inspectors will be selected for use and you will receive an empty report)
*-SelectedInspectors* : Selects only  specific inspectors you would like (For versions earlier than 1.1, this does not work properly. )
*-ExcludedInspectors* Excludes specific inspectors you provide within the parameter (For versions earlier than 1.1, this does not work properly. )

### 5.3 Execution Examples
In normal situations when using the standard command to execute a security assessment you will be prompted with graphical login screens where you must sequentially log into. 

Get-M365SATReport -OrgName "Contoso" -OutPath "C:\out" -reportType HTML

For semi-automation you should specify the -Username parameter that would allow logging in into some of the modules automatically. Sadly there are some modules where it is required to login with full credentials, we cannot mitigate this issue. So we have to wait for an update in the future to allow the support of this functionality.

The command below has provided an Username. If the user has already cached credentials, only for MSOnline logging in is required. The rest either goes automatically or only a password with MFA is required depending on the tenant's configuration settings:

Get-M365SATReport -OrgName "Contoso" -OutPath "C:\out" -Username "example@contoso.org" -reportType HTML 

The command below provides the same, except it skips the pre-checks such as  program updates, module updates, duplicate checks and module existence assuming that all modules are up-to-date, installed and there are no duplicates and uses custom modules saved in the inspectors folder

Get-M365SATReport -OrgName "Contoso" -OutPath "C:\out" -Username "example@contoso.org" -reportType HTML -SkipChecks -UseCustomModules

Depending on the capacity of the organization, M365SAT may take some time to execute. For organizations with a tiny amount of user accounts and none to little configuration M365SAT will not take longer than 5 minutes. For organizations that have more than 100 accounts and more custom configurations it would take longer. It all depends on how large and complex the organization is and how much is configured. 

## 6. Development
Unlike 365Inspect+, M365SAT is far more modular than its predecessor. Besides the design to expand easily additional modules can now be easily expanded or troubleshooted when occuring problems. We have divided muliple modules into directories so when an user builds a new module they can easily create a new directory and develop the new module. 

### 6.1 Developing Inspector Modules
All Inspector modules are stored in the .\inspectors folder. You can use any earlier created module as a template to create a new module. Most of the modules are called:

*{ProductFamily}-{Thethingyouwanttocheck}.ps1*

For ProductFamily we have the following options at the moment:
- Microsoft Azure
- Microsoft Office 365
- Microsoft Exchange
- Microsoft Teams
- Microsoft SharePoint

#### 6.1.1 Example
The following example:

````
# This is an SharepointModernAuthentication Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks if SharePoint Modern Authentication is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SharepointModernAuthentication($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0008"
		FindingName	     = "SharePoint Online Modern Authentication is Not Enabled"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "9.3"
		Description	     = "Modern Authentication is a SharePoint Online setting that allows authentication features such as MFA, smart cards, and certificate-based authentication to function. These authentication features, particularly MFA, are vital for the secure operation of an organization. It is recommended to enable SharePoint modern authentication."
		Remediation	     = "Use the PowerShell Script to mitigate the issue."
		DefaultValue	 = "False"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOTenant -OfficeClientADALDisabled $false'
		References	     = @(@{ 'Name' = 'Reference - Set-SPOTenant'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' })
	}
}


function Inspect-SharepointModernAuthentication
{
	Try
	{
		
		$sharepoint_modern_auth_disabled = $(Get-SPOTenant).OfficeClientADALDisabled
		If ($sharepoint_modern_auth_disabled)
		{
			$setting = (Get-SPOTenant).OfficeClientADALDisabled
			$endobject = Build-SharepointModernAuthentication($setting)
			return $endobject
		}
		return $null
		
	}
	Catch
	{
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
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
	
}

return Inspect-SharepointModernAuthentication
````

To briefly explain the parts above:
- First, you have a comment description including the date of creation, version, author and purpose of the inspector,
- Second, you have the errorhandling scripts that are loaded into the program. There is a common bug with it as in future releases this will be fixed. Then the so-called Error-Logger will be called from outside of the script instead of copying the whole error-logger within the script
- Third, optionally if your script has logs to export you can use the *$path = @($OutPath)* to make sure the logs are being put into the correct folder
- Fourth, The 'Build' Function containing the information if violation of the inspector is found the Build function can be executed to create a CustomPSObject to return for the report.
- Fifth, the actual script that checks if there is any violation. You must use return $endobject and $endobject = Build-{Yourinspectorname}(x) as x is the information you want to pass to the build function to fill the PSCustomObject with so the findings can be reported back into the report

Some Coding Tips:
 - Use try & catch in case if your inspector has problems the output will return null or an exception will be thrown. The output those errors can be found in the same directory into an additionally created log directory where the errorlogs are placed.
 - Try to use as less code as possible. Long strings of code will delay the overall performance and makes the security assessment much longer than usual
 - If you really want to make beautiful well-formatted PowerShell Inspectors. Take a look at SAPIEN PowerShell Studio. It has a nice Format-Script function that allows you to very much format the script into readable parts to save you time finding issues if there are any.

### 6.2 Developing Additional Modules
You can develop additional modules and place them either in the .\modules if it is a pre-check module or in the core module if it is an addition to the core of the program. If you develop a new way to output a report into a different file you can place the so-called 'parser' into the .\output folder

## 7. About M35SAT's Security
Me as a Vulnerability Assessor take security very seriously. Take in mind that this program can execute other inspector modules. That means even malicious scripts can be ran if wanted. I am not responsible for any damage or loss of files if that is the case.

Please use the security best-practices as followed:
- Use least privilege on the account you audit with. So only the necessary privileges for the audit being used on the account you are provided with,
- Write-Protect the inspector folder for unauthorized access to make sure your inspectors are not being overwritten with malicious code,
- Do not place, unless it is trusted, any PowerShell script into the inspectors folder

## 8. License

M365SAT is an open-source and free software released under the [MIT License](https://github.com/asterictnl-lvdw/M365SAT/blob/main/LICENSE).

## 9. Special Thanks To...
* [SoteriaSecurity](https://github.com/soteria-security/365Inspect): For allowing me to create the fork on the predecessor!
* [CISSecurity](https://www.cisecurity.org/cis-benchmarks/): For providing the Azure and Microsoft 365 benchmarks to make the inspector modules
