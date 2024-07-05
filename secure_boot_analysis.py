#!/usr/bin/env python3

import os
import subprocess
import re
import sys
from datetime import datetime
import argparse
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    logger.error("requests module not found. Please install it using 'pip install requests'")
    sys.exit(1)

def execute_command(command):
    logger.debug("Executing command: %s", command)
    try:
        output = subprocess.check_output(command, shell=True, universal_newlines=True, stderr=subprocess.STDOUT)
        logger.debug("Command output:\n%s", output)
        return output
    except subprocess.CalledProcessError as e:
        logger.error("Command failed: %s", e)
        logger.debug("Error output:\n%s", e.output)
        return None

def check_secure_boot():
    logger.info("Checking Secure Boot status...")
    try:
        with open('/sys/kernel/security/securelevel', 'r') as f:
            securelevel = f.read().strip()
        secure_boot_enabled = int(securelevel) > 0
        logger.info("Secure Boot is %s", 'enabled' if secure_boot_enabled else 'disabled')
        return secure_boot_enabled, "Securelevel: " + securelevel
    except FileNotFoundError:
        logger.warning("Secure Boot status could not be determined (securelevel file not found)")
        return False, "Securelevel file not found"

def check_weak_configurations():
    logger.info("Checking for weak configurations...")
    weak_configs = []
    poc_logs = []
    paths_checked = []
    
    # Check for unsigned kernel modules
    paths_checked.append("/proc/modules")
    logger.info("Checking for unsigned kernel modules...")
    lsmod_output = execute_command('lsmod')
    if lsmod_output and 'unsigned' in lsmod_output.lower():
        weak_configs.append("Unsigned kernel modules detected")
        poc_logs.append("lsmod output:\n" + lsmod_output)
    else:
        logger.info("No unsigned kernel modules detected")
    
    # Check for disabled module signature verification
    paths_checked.append("/proc/sys/kernel/modules_disabled")
    logger.info("Checking module signature verification status...")
    try:
        with open('/proc/sys/kernel/modules_disabled', 'r') as f:
            modules_disabled = f.read().strip()
            if modules_disabled == '0':
                weak_configs.append("Module signature verification is disabled")
                poc_logs.append("modules_disabled: " + modules_disabled)
            else:
                logger.info("Module signature verification is enabled")
    except FileNotFoundError:
        logger.warning("Unable to check module signature verification status")
        weak_configs.append("Unable to check module signature verification status")
    
    return weak_configs, poc_logs, paths_checked

def check_cve_vulnerabilities():
    logger.info("Checking for CVE vulnerabilities...")
    cve_list = []
    poc_logs = []
    
    cve_urls = [
        "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=secure+boot",
        "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=uefi"
    ]
    
    for url in cve_urls:
        logger.info("Querying %s", url)
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                cves = re.findall(r'CVE-\d{4}-\d{4,7}', response.text)
                cve_list.extend(cves)
                poc_logs.append("CVEs found from " + url + ": " + ', '.join(cves))
            else:
                logger.warning("Received status code %d from %s", response.status_code, url)
        except requests.RequestException as e:
            logger.error("Error fetching CVE information from %s: %s", url, e)
            cve_list.append("Unable to fetch CVE information from " + url)
    
    # Only keep top 10 CVEs
    cve_list = cve_list[:10]
    return cve_list, poc_logs

def check_advanced_secure_boot():
    logger.info("Performing advanced Secure Boot check...")
    findings = []
    poc_logs = []
    paths_checked = []

    secure_boot_files = [
        '/sys/firmware/efi/efivars/SecureBoot-*',
        '/sys/firmware/efi/vars/SecureBoot-*',
        '/sys/firmware/efi/securebool',
        '/boot/efi/EFI/BOOT/bootx64.efi',
        '/boot/efi/EFI/ubuntu/grubx64.efi',
        '/etc/grub.d/30_uefi-firmware',
    ]

    for file_path in secure_boot_files:
        logger.info("Checking %s", file_path)
        output = execute_command("ls -l " + file_path)
        if output:
            findings.append("Found Secure Boot related file: " + file_path)
            poc_logs.append("File check output for " + file_path + ":\n" + output)
        paths_checked.append(file_path)

    # Check UEFI configuration
    logger.info("Checking UEFI configuration")
    efibootmgr_output = execute_command("which efibootmgr && efibootmgr -v || echo 'efibootmgr not found'")
    if efibootmgr_output:
        findings.append("UEFI boot entries found")
        poc_logs.append("UEFI boot entries:\n" + efibootmgr_output)

    # Recursively check /boot directory
    logger.info("Recursively checking /boot directory")
    boot_files = execute_command("find /boot -type f")
    if boot_files:
        findings.append("Boot directory contents listed")
        poc_logs.append("Boot directory contents:\n" + boot_files)

    return findings, poc_logs, paths_checked

def check_firmware_files():
    logger.info("Checking for firmware files in root directory...")
    firmware_files = []
    poc_logs = []

    for root, dirs, files in os.walk('/'):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(('.bin', '.img')) and os.path.getsize(file_path) < 1024 * 1024 * 100:  # 100MB limit
                firmware_files.append(file_path)
                poc_logs.append("Found firmware file: " + file_path)

    return firmware_files, poc_logs

def get_cve_description(cve_id):
    url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve_id
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            description = re.search(r'<th colspan="2">Description</th>.*?<td>(.*?)</td>', response.text, re.DOTALL)
            if description:
                return description.group(1).strip()
    except requests.RequestException as e:
        logger.error("Error fetching CVE description: %s", e)
    return "Description not available"

def generate_html_report(secure_boot_enabled, secure_boot_poc, weak_configs, weak_configs_poc, cve_list, cve_poc, advanced_findings=None, advanced_poc=None, firmware_files=None, firmware_poc=None, paths_checked=None):
    html_content = [
        "<!DOCTYPE html>",
        "<html lang=\"en\">",
        "<head>",
        "    <meta charset=\"UTF-8\">",
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
        "    <title>Secure Boot Analysis Report</title>",
        "    <style>",
        "        body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }",
        "        h1 { color: #333; }",
        "        h2 { color: #666; }",
        "        .section { margin-bottom: 20px; }",
        "        .warning { color: #e74c3c; }",
        "        .poc { background-color: #f1f1f1; padding: 10px; border-radius: 5px; }",
        "        table { width: 100%; border-collapse: collapse; }",
        "        table, th, td { border: 1px solid black; }",
        "        th, td { padding: 8px; text-align: left; }",
        "    </style>",
        "</head>",
        "<body>",
        "    <h1>Secure Boot Analysis Report</h1>",
        "    <p>Generated on: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "</p>",
        "",
        "    <div class=\"section\">",
        "        <h2>Summary</h2>",
        "        <p>Secure Boot Status: " + ('Enabled' if secure_boot_enabled else 'Disabled') + "</p>",
        "        <p>Weak Configurations Found: " + str(len(weak_configs)) + "</p>",
        "        <p>Potential CVE Vulnerabilities: " + str(len(cve_list)) + "</p>",
        "        <p>Firmware Files Found: " + str(len(firmware_files) if firmware_files else 0) + "</p>",
        "    </div>",
        "",
        "    <div class=\"section\">",
        "        <h2>Secure Boot Status</h2>",
        "        <p>" + ('Enabled' if secure_boot_enabled else 'Disabled') + "</p>",
        "        <h3>Proof of Concept:</h3>",
        "        <pre class=\"poc\">" + secure_boot_poc + "</pre>",
        "    </div>",
        "",
        "    <div class=\"section\">",
        "        <h2>Weak Configurations</h2>",
        "        " + ('<p class="warning">No weak configurations found.</p>' if not weak_configs else ''),
        "        <ul>",
        "            " + ''.join("<li class=\"warning\">" + config + "</li>" for config in weak_configs),
        "        </ul>",
        "        <h3>Paths Checked:</h3>",
        "        <pre class=\"poc\">" + '\n'.join(paths_checked) + "</pre>",
        "        <h3>Proof of Concept:</h3>",
        "        <pre class=\"poc\">" + ''.join(weak_configs_poc) + "</pre>",
        "    </div>",
        "",
        "    <div class=\"section\">",
        "        <h2>Potential CVE Vulnerabilities</h2>",
        "        <table>",
        "            <thead>",
        "                <tr>",
        "                    <th>CVE ID</th>",
        "                    <th>Description</th>",
        "                </tr>",
        "            </thead>",
        "            <tbody>",
        "                " + ''.join("<tr><td>" + cve + "</td><td>" + get_cve_description(cve) + "</td></tr>" for cve in cve_list),
        "            </tbody>",
        "        </table>",
        "        <h3>Proof of Concept:</h3>",
        "        <pre class=\"poc\">" + ''.join(cve_poc) + "</pre>",
        "    </div>",
    ]

    if advanced_findings:
        html_content.extend([
            "    <div class=\"section\">",
            "        <h2>Advanced Secure Boot Check</h2>",
            "        <ul>",
            "            " + ''.join("<li>" + finding + "</li>" for finding in advanced_findings),
            "        </ul>",
            "        <h3>Proof of Concept:</h3>",
            "        <pre class=\"poc\">" + ''.join(advanced_poc) + "</pre>",
            "    </div>",
        ])

    if firmware_files:
        html_content.extend([
            "    <div class=\"section\">",
            "        <h2>Firmware Files Found</h2>",
            "        <ul>",
            "            " + ''.join("<li>" + file + "</li>" for file in firmware_files),
            "        </ul>",
            "        <h3>Proof of Concept:</h3>",
            "        <pre class=\"poc\">" + ''.join(firmware_poc) + "</pre>",
            "    </div>",
        ])

    html_content.extend([
        "</body>",
        "</html>",
    ])
    
    with open('secure_boot_report.html', 'w') as f:
        f.write('\n'.join(html_content))

def main():
    parser = argparse.ArgumentParser(description="Secure Boot Analysis Tool")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('-m', '--mode', type=int, choices=[1, 2], default=1, help="1: Basic check, 2: Advanced check")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("Starting Secure Boot analysis...")

    secure_boot_enabled, secure_boot_poc = check_secure_boot()
    weak_configs, weak_configs_poc, paths_checked = check_weak_configurations()
    cve_list, cve_poc = check_cve_vulnerabilities()
    firmware_files, firmware_poc = check_firmware_files()

    if args.mode == 2:
        logger.info("Performing advanced Secure Boot check...")
        advanced_findings, advanced_poc, advanced_paths_checked = check_advanced_secure_boot()
        paths_checked.extend(advanced_paths_checked)
        generate_html_report(secure_boot_enabled, secure_boot_poc, weak_configs, weak_configs_poc, cve_list, cve_poc, advanced_findings, advanced_poc, firmware_files, firmware_poc, paths_checked)
    else:
        generate_html_report(secure_boot_enabled, secure_boot_poc, weak_configs, weak_configs_poc, cve_list, cve_poc, firmware_files=firmware_files, firmware_poc=firmware_poc, paths_checked=paths_checked)

    logger.info("Report generated: secure_boot_report.html")

if __name__ == "__main__":
    main()
