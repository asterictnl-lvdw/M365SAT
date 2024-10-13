# TO-DO List

### TO-DO (v3.0)
- Object-Sorting Fix, due to a bug where the sorting was not correctly done resulting into a messed up report [#47](https://github.com/asterictnl-lvdw/M365SAT/issues/47) **ON-HOLD**
- I have optimized multiple Azure related audit scripts to ensure you can optimally audit environments.
- I have added the v3.0.0 inspectors to the list of availability.
- Removal of all v2.x.x Inspectors to rewrite them all based on the v3.x.x inspectors which are more accurate.
- Multiple Conditional Access Enhancements where possible to improve accuracy with auditing **DONE**
- Fully cross-platform compatibility (including MacOSX and Linux) **TESTING**
- [#37](https://github.com/asterictnl-lvdw/M365SAT/issues/37) **IN-PROGRESS**
- [#39](https://github.com/asterictnl-lvdw/M365SAT/issues/39) **DONE**
- Creating a Docker-Container of M365SAT to run a containerized environment.
- Improve the CSV output support **IN-PROGRESS**
- Add XML and JSON support as output possibility **IN-PROGRESS**
- There is no detection for government issued environments and I do not know if the script does work for it. **DONE**
- Looking into the implementation with a service principal instead of a global admin account with respective permissions.
- Implementing the CISA Benchmark and creating a mapping with the CIS benchmark. **IN-PROGRESS**
- Make a risk distribution Chart en make the other chart responsive instead of a static chart. **ON-HOLD**
- Add the posibility for 1-click remediation as you execute the PowerShell command via the browser by executing the command in the browser to look at this possibility.
- We are going to start using PnP.Powershell alongside the Microsoft Sharepoint module to PnP PowerShell, due to wider compatibility and better support. **ON-HOLD**
- Add additional objects within the finding-objects to enhance reporting mechanism. (Paragraph, Status) **IN-PROGRESS**
- Add the OK status so you will get a report including the things that are OK as well. (3-status-mechanism: OK,FAIL,UNKNOWN). **IN-PROGRESS**
- Replaced the AzAccount MultiAPI Connector with a no dependency connector, the only thing is that you need to authenticate once to gather the token to authenticate to the endpoints. **IN-PROGRESS**

### Unknown

- We are going to widen the compatibility of MultiThreaded-Mode.
- There are issues with MultiThreading when running Exchange Cmdlets. Source: https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps we are looking into implementing the workaround to make this work so multithreading will be no issue with these cmdlets. Eventually these cmdlets will be executed in singlethreaded mode afterwards to make sure they succeed all.
- There are multiple issues with multithreading mode when executing the inspectors. This is being investigated, but there is no fix available at this moment. When this will be fixed is unknown.