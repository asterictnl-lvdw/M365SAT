# Project TO-DO List

## Version 3.0 Release

### Fixes (v3.0)
- All possible fixes have been implemented for now.

### Implemented Features
- **Cross-Platform Compatibility**: Achieved compatibility with MacOS and Linux. **Status: TESTING**
- **Government Environments**: Uncertain compatibility with government-issued environments; further testing required. **Status: TESTING**

### Ongoing Fixes
- **Report Status Enhancement**: Introduce a 3-status reporting mechanism (OK, FAIL, UNKNOWN) to include successfully passed checks in the report. **Status: IN-PROGRESS**
- **Finding-Objects Expansion**: Add new objects to enhance reporting, including Paragraph and Status attributes. **Status: IN-PROGRESS**
- **AzAccount MultiAPI Replacement**: Replacing AzAccount MultiAPI Connector with a no-dependency connector; requires a one-time authentication for token generation. **Status: POSTPONED**
- [Issue #37](https://github.com/Karmakstylez/M365SAT/issues/37) **Status: IN-PROGRESS**
- **CSV Output Improvement**: Enhance CSV output functionality for better data handling. **Status: M365 Converted, Azure IN-PROGRESS**
- **XML/JSON Output Support**: Add support for XML and JSON as additional output formats. **Status: IN-PROGRESS**
- **Service Principal Integration**: Explore using a service principal instead of a global admin account for operations, ensuring proper permissions. **Status: IN-PROGRESS**
- **CISA Benchmark Implementation**: Integrate CISA Benchmark and create mappings with the CIS Benchmark. **Status: IN-PROGRESS**

### Investigation & Future Tasks
- **Docker-Container Creation**: Develop a Docker container version of M365SAT for containerized environments. **Status: DELAYED**
- **Multi-Threaded Compatibility**: Explore wider compatibility for Multi-Threaded Mode execution. **Status: UNDER INVESTIGATION**
- **Exchange Cmdlets Multi-Threading Issues**: Address multithreading compatibility issues when running Exchange Cmdlets. Workarounds from [Microsoft](https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps) are under review. If unresolved, cmdlets will execute in single-threaded mode to ensure stability.
- **Inspector Multi-Threading Issues**: Ongoing investigation into multithreading challenges with inspector execution. No current fix or timeline available. 