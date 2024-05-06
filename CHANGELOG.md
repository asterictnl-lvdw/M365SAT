# v1.0.0beta 1-2-2023
The brand new release is now ready to be tested in beta. Warning: This is a BETA! Some parts of code might be unstable or not working properly. We are aware of issues and they will be eliminated in the stable version.

## What is New?
-	365Inspect+ has been changed to M365SAT
-	A brand new reporting engine that allows a much better overview of issues within your tenant. Besides that the report looks much more professional.
-	I have created the option to import M365SAT as a module or to run it the old way like 365Inspect+ did by executing a .ps1 script. In the future the release will also be installable through the PowerShell Gallery
-	Thanks to a change in the code less sensitive permissions are needed instead of Global Administrator. Global Reader and SharePoint Administrator will do the job now. SharePoint Administrator is still a sensitive permission, but because in the other roles of SharePoint it is not possible to read various values that are essential to audit SharePoint correctly.
-	We have removed the .json files for now and fused it with the .ps1 scripts. Now when the issue is found it will call a function that will return an PSCustomObject which is must faster than importing .json all the time. Leading to performance optimalization 
-	Some generic optimalization by changing some code within the engine
-	Added more console output where you can directly see if there are issues with inspectors finding things violating policy, etc.
-	The structure of modules is different. Now additional modules can be added to the script if needed. This makes the program even more modular 
-	Fixes output of the PowerShellScript where the remediation script was incorrectly displayed because of double quotes instead of single quotes
-	Added even more remediation powershell script possibilities to allow possibility to automate remediation of most scripts in the future
-	Categorized all modules within the report and by naming them e.g. {category}-{check}
-	CVSS 3.1 Scores are added within calculation. Based what could happen if the misconfiguration is abused
-	All modules have now an unique ID. In the future an list will be made with remediation so you can easily tell which issue has been found and how to remediate it. 
-	Optmized various inspectors code
-	Allowed easier authentication by providing username 

## Known Issues:
-	There is an issue with the ErrorLog not correctly capturing the message when an exception is thrown. The ErrorLog will be rewritten in the upcoming release
-	Some of the logs output are not being saved in the correct location. This will be fixed in the upcoming release
-	The online inspector download tool is not working yet, this is because the inspectors have not been published to the GitHub repository yet. 
-	The healthindex is not round and calculated correctly, thus looking a bit ugly, this will be fixed in the upcoming release.
-	There might be duplicates in some of the inspectors. This will be checked and fixed in the upcoming release
-	PowerShell 7 is partially compatible, but could result in a lot of bugs and code not working properly. It is still in the testing phase. If you encounter issues, please switch back to PowerShell 5.x and run the audit there. 
-	The updating mechanism to check for an update of M365SAT is not working properly yet, because it has not been published to GitHub yet. In future releases this will be briefly tested to check if this is working properly.
-	Some documentation might be added later

## To Implement:
-   Get-NetRoute | ? DestinationPrefix-eq '0.0.0.0/0' | Get-NetIPInterface | Where ConnectionState-eq 'Connected' (Which is for checking Network Connection)

# Version 2.0

Finally it is here! After a long time of developing, bugfixing and testing I am finally able to release the v2.0 of Microsoft 365 Security Assessment Tool (M365SAT).

Many things have been changed, added, removed and fixed. I have made a comprehensive list for you to see what has changed:

## What is new:
-   Updated the CIS benchmark to the latest v2.0.0 for both Microsoft Azure and Microsoft 365
-   We have added parameters that can select which benchmark you want to check. In the future I will see if I can add another benchmark as well. Please do tell which benchmarks you are interested in so I can see what requirements are needed.
-   Added brand new inspectors that enable new findings for both your Microsoft Azure and Microsoft 365 environment
-   Removed some duplicate inspectors at multiple productfamilies
-   Instead of 119 inspectors we now have 177 inspectors (this includes custom inspectors as well)
-   We are testing a new login mechanism that allows better management when problems occur 
-   We implemented a custom API caller which enables us to gain settings within the Azure tenant and other portals as well.
-   We have added a M365SATTester.ps1 script that can be ran if you want to make use of M365SAT
-   We have enabled autodetection for Sharepoint domains thanks to Soteria
-   We have added a copy button onto the remediation script which allows easy copy of the remediation script where available.
-   We have made the PowerShell scripts better readable thanks to Soteria and some additions
-   We have changed the collapse menu's to a different style thanks to Bootstrap 5 with responsive chevrons for more professionalism
-   We have added more Read permissions to Microsoft Graph to read further settings that are required for the CIS benchmark
-   All Inspectors are working onto their latest version. And will be tested again once updates occur to see if there are any issues.
-   M365SAT is partially compatible with PowerShell 7 now.
-   We have enabled that you can execute M365SAT with lesser permissions now than Global Administrator.

## Fixed:
-   We have fixed the HealthIndex in the report which is now cleanly a round number and gives now the correct health index. The problem was that the 100 was not deducted by the score resulting in a weaker score than it would be
-   We have fixed issues with some priorities not displaying correctly as some informational noted inspectors were not sorted correctly
-   We have fixed performance related issues with the Exchange cmdlets that have now less time needed to process thanks to the EXO cmdlets.
-   We have fixed some logging issues where logs were not saved in the correct place resulting into errors if the directory was not created
-   Fixed issues with the DMARC, DKIM and SPF records verification which is now done entirely by PowerShell commands instead of CMD commands
-   Fixed resizing issues with the HTML report by removing multiple flex classes. Now if you make your screen smaller the objects will be smaller as well.
-   We have fixed an issue that enabled correctly sorting the CVS 
-   There was an issue with the start and end date in the report, this has been fixed so the correct start-date and end-date is written in the report now

## Changed:
-   We have renamed multiple ps1 files to make their function more readable
-   I have moved some things around in the report structure
-   I have moved the inspector list to the end of the report to display all neccesary information first.
-   Have updated all depedencies into the HTML report to their latest versions.
-   I have migrated the Exchange commands to the new EXO cmdlet commands (V3) for better stability and performance.
-   We have switched the authentication that Security & Compliance goes first and then Exchange due to a bug in the REST Schema that does not allow Exchange cmdlets to succeed when the Exchange cmdlet is being connected before the S&C Cmdlet
O I have migrated Bootstrap 4 to Bootstrap 5 which enhances the prettiness of the report
O I have updated the JQuery and FontAwesome dependencies to their latest version without any issues. 

## Removed:
-    We have said goodbye to the PnPPowerShell modules for now as we want to take full potential of the Sharepoint Cmdlet
-    We have said goodbye to the AzureADPreview and MicrosoftOnline (MSOL) modules as they will be phased out by Microsoft and replaced by Microsoft Graph
-    We have said goodbye to the Microsoft InTune module which is now fully implemented in Microsoft Graph itself
-    We have removed the Write-ErrorLog.ps1 and replaced it with PoSHLog which allows us better logging as it looks more clean. 

## Known Issues and Bugs:
-   Logfiles are not pointed to the correct folder. This will be fixed in the upcoming release. You can manually open the corresponding txt file as a workaround for now. This has to do with the directory created in a later phase as we will create the directory earlier in the upcoming release
-   The CVS might have incorrect scores. I will change the scores based on CWE findings and based onto a custom priority algorithm to determine what has big priority for general users and what has not.
-   Some modules require manual authentication due to their cmdlet does not support cached credentials authentication.
-   On PowerShell 5.1 CISAz6000 gives an warning about 'Microsoft.Azure.PowerShell.Cmdlets.Network'. This can be safely ignored. In the next release I will check if I can supress the issue
-   Not all Text files have the correct naming yet. This will be fixed in the next upcoming release.
-   There might be duplicate logs of some findings. This is due some objects have more than 10 stored into the array. We will be fixing the issue so objects are automatically pointed to output in the next release
-   The Clipboard function does not work with all internet browsers. If you are encountering issues, please open the html file in a different browser e.g. Microsoft Edge
-   In PowerShell 7 the following inspectors do not work: CISMEx230, CISMEx280, CSTM-Ex013, CSTM-Ex014, CSTM-Ex015, CSTM-Ex016, CSTM-Ex023, CSTM-Ex024, CSTM-Ex025, CSTM-Ex026 and CSTM-Ex027. This has to do with some issues within the new EXO commands that are not entirely working properly with PowerShell 7 yet. Only Exchange is impacted for now. We are looking to revert back from EXO to the normal commands in some test-releases to see if that resolves the issue for now and archive the EXO inspectors for later use.

# Version 2.1
Finally after a long while and postponing the release several times I am happy to announce version 2.1 of M365SAT with a bunch of new updates.

## What is new:
-   Updated the Microsoft 365 CIS benchmark to the latest v3.0.0 
-   We added a parameter for the ones who still want to use the CIS v2.0 benchmark of Microsoft 365
-   We have added a multi-threading mode as expirimental function. Do check the limitations, because there are some problems with it. The implementation is done with ThreadJobs. In PS7+ this is already available and for PS5 you must install an additional module in order to make this work. The reason we did this is because we want to make the scanning experience as fast as possible. Since the scans are not depending on eachother we can simply put them in multiple threads. Normal jobs did not seem to work since they create an new session, thus requiring us to authenticate again for each inspector which creates large delays. Since ThreadJobs stay in the same PowerShell windows but create backgroundjobs that stay in the same session we are allowed to re-use the commands.
-   I have added the Likelihood and Priority objects within all the inspectors. This to calculate the RiskScore. Every RiskScore is calculated by multiplying the impact with the likelihood. A RiskScore can be between 0 and 25. Where 0 is always informational and 25 is Critical. For the exact numbers please consult the README.md published on GitHub.

## Fixed:
We fixed some issues with styling in the report as well as some descriptions from CIS misconfigurations

## Changed:
-   I have changed the CVSS with a risk analysis model based on impact x likelihood
-   We have made a change to the priority schema. Things were not as critical or high sometimes that decided us to change things around to allow your organization better prioritizing your findings. We have decided to use a 5x5 Risk Analysis Schema to determine the severity and priority instead of the score.
-   We have modified the sort-object schema as we are now sorting on the RiskScore.
-   We have provided an update to the README.md to make some text more clear

## Removed:
-   We have removed the CVSS score as it was not accurate. Not every CIS thing fixes a vulnerability.

## Known Issues
-   The sorting of the objects it not yet fixed, the priority is correct, but the riskrating sort is not correctly implemented yet. This will be fixed in the next release (v2.1.1)
-   It might happen that some sources have to be changed due to the new implementation. This will be fixed in the next release (v2.1.1)
-   CISMAz1111 is not working in multithreaded mode on PowerShell v5 (INVESTIGATION) there are multiple issues with multithreading mode when executing the inspectors.
-   There are issues with MultiThreading when running Exchange Cmdlets. Source: https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps we are looking into implementing the workaround to make this work so multithreading will be no issue with these cmdlets. Eventually these cmdlets will be executed in singlethreaded mode afterwards to make sure they succeed all. (INVESTIGATION)

# Version 2.1.1
Finally after a long while of testing and implementing new stuff, I am happy to announce version 2.1.1 of M365SAT with a bunch of new updates.

## What is new:
-   Updated the Azure Foundations CIS benchmark to the latest v2.1.0 and added as many as possible checks to ensure you can check as much as possible for the CIS Benchmark and expanding coverage.
-   We have added an option in the AuditType parameter called 'Latest' which enabled users to audit their environment based on the latest checks (M365: v3.0.0 and AZ: v2.1.0). This is now also the default option
-   We have fixed some issues regarding some inspectors and removed some uneccesary warning message decreasing performance.

## Fixed:
-   There were some issues regarding time-out that have been investigated and have been fixed in v3.0.0 and v2.1.0. 

## Changed:
-   There are no major changes

## Removed:
-   There were no removals done this release

# Version 2.2

## Added
-   E3 / E5 TAG ADDING (E3 Level 1, E3 Level 2, E5 Level 1, E5 Level 2) including parameters
-   The 'EnvironmentType' parameter has been added to distinguish Microsoft 365 and Azure from eachother
-   The 'LicenseMode' parameter has been added to distinguish an E3 from an E5 audit or the otherway around or if you want to audit both that is possible as well now
-   The 'LicenseLevel' has been added based on the CIS since the CIS defines two types of levels as one has more impact than the other. The user can now choose to only audit on the level 1 parts, or only the level 2 or both
-   Multiple options to run a script are now possible in the M365SATTester.ps1 file
## Fixed
-   The sources of findings have been fixed just as well as some of the descriptions
-   Some incorrect change have been improved to their latest version in v3.0.0 of the M365 Inspector list
## Changed
-   There have been multiple parameters being removed
-   The BenchmarkVersion has been changed to allow better processing and using only the specific benchmark version instead of all benchmarks
-   The 'Modules' parameter have been changed
-   Changed the name of the CustomModules to LocalMode
-   There have been some changes within the Connection Schema allowing if only specific modules are needing to be scanned that you only need to authenticate the corresponding modules and not all modules anymore instead
-   We are expirimenting with outputting all findings to .txt file as well and to see what impact it has on performance. If it eats too much memory and affects performance we will remove this in a future release
## Removed
-   There were no removals done this release
## Known Issues

*See the TODO.md for what needs to be done for version 2.3*