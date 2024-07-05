# Secure Boot Analysis Tool

## Description
This Python script performs a comprehensive analysis of system security features related to Secure Boot, weak configurations, potential CVE vulnerabilities, and firmware files. It generates an HTML report summarizing the findings.

## Features
- **Secure Boot Status Check:** Determines whether Secure Boot is enabled or disabled.
- **Weak Configurations Detection:** Checks for unsigned kernel modules and disabled module signature verification.
- **CVE Vulnerability Check:** Fetches and lists potential CVE vulnerabilities related to Secure Boot and UEFI.
- **Advanced Secure Boot Check:** Includes additional checks such as examining Secure Boot related files, UEFI configurations, and `/boot` directory contents.
- **Firmware Files Analysis:** Searches for firmware files in the root directory.

## Requirements
- Python 3.x
- Required Python packages: `requests`

## Usage
1. **Installation**:
   - Ensure Python 3.x is installed.
   - Install required packages:
     ```bash
     pip install requests
     ```

2. **Execution**:
   - Run the script with Python:
     ```bash
     python secure_boot_analysis.py [-v] [-m {1,2}]
     ```
     - `-v, --verbose`: Enable verbose output.
     - `-m {1,2}, --mode {1,2}`: Select mode (1: Basic check, 2: Advanced check).

3. **Output**:
   - The script generates an HTML report (`secure_boot_report.html`) summarizing the analysis findings.

## Example
```bash
python secure_boot_analysis.py -v -m 2
```

This command runs the script in verbose mode with advanced check enabled.
