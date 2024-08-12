## TO-DO (v2.3)
-   The sorting of the objects it not yet fixed, the priority is correct, but the riskrating sort is not correctly implemented yet. **IN-PROGRESS**
-   The exception will be a seperate module as this is much simpler than raising the same exception everytime. **PARTIALLY FIXED**
-   The main Directory will be created earlier to get the new path name so the logfiles will be stored in the correct folder and pointed to the correct folder **PARTIALLY FIXED**
-   The permissions schema of Microsoft Graph will be changed in the next release. Someone else will scan which permissions are neccesary to implement **DONE**
-   [#34](https://github.com/asterictnl-lvdw/M365SAT/issues/34) **DONE**
-   [#38](https://github.com/asterictnl-lvdw/M365SAT/issues/38) **DONE**
-   [#40](https://github.com/asterictnl-lvdw/M365SAT/issues/40) **IN-PROGRESS**

### Next Major Release (3.0)
-   [#37](https://github.com/asterictnl-lvdw/M365SAT/issues/37) **NEXT-MAJOR-RELEASE**
-   [#39](https://github.com/asterictnl-lvdw/M365SAT/issues/39) **NEXT-MAJOR-RELEASE**
-   Fully cross-platform compatibility by removing as many platform dependencies and replacing them by initiating them via API connections. (v3.0)
-   There is no detection for government issued environments and I do not know if the script does work for it (v3.0)
-   Looking into the implementation with a service principal instead of a global admin account with respective permissions (v3.0)
-   Implementing the CISA Benchmark
-   Make a risk distribution Chart en make the other chart responsive instead of a static chart (v3.0)
-   Add the posibility for 1-click remediation as you execute the PowerShell command via the browser by executing the command in the browser to look at this possibility (v3.0)
-   We are going to start using PnP.Powershell alongside the Microsoft Sharepoint module to PnP PowerShell, due to wider compatibility and better support. This will be implemented in v3.0
-   Add additional objects within the finding-objects to enhance reporting mechanism
-   Add the OK status so you will get a report including the things that are OK as well. (3-status-mechanism: OK,FAIL,UNKNOWN)

### Unknown
-   We are going to widen the compatibility of MultiThreaded-Mode
-   There are issues with MultiThreading when running Exchange Cmdlets. Source: https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps we are looking into implementing the workaround to make this work so multithreading will be no issue with these cmdlets. Eventually these cmdlets will be executed in singlethreaded mode afterwards to make sure they succeed all.
-   There are multiple issues with multithreading mode when executing the inspectors. This is being investigated, but there is no fix available at this moment. When this will be fixed is unknown 