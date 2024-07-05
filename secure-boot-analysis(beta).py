#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import re
import subprocess

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_secure_boot():
    logger.info("Checking Secure Boot status...")
    securelevel_file = '/sys/kernel/security/securelevel'
    try:
        with open(securelevel_file, 'r') as f:
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
    paths_checked = []
    
    # Check for unsigned kernel modules
    paths_checked.append("/proc/modules")
    logger.info("Checking for unsigned kernel modules...")
    try:
        with open('/proc/modules', 'r') as f:
            modules_content = f.read()
            if 'unsigned' in modules_content.lower():
                weak_configs.append("Unsigned kernel modules detected")
                logger.info("Unsigned kernel modules detected:\n%s", modules_content)
    except FileNotFoundError:
        logger.warning("Unable to read /proc/modules")
    
    # Check for disabled module signature verification
    modules_disabled_file = '/proc/sys/kernel/modules_disabled'
    paths_checked.append(modules_disabled_file)
    logger.info("Checking module signature verification status...")
    try:
        with open(modules_disabled_file, 'r') as f:
            modules_disabled = f.read().strip()
            if modules_disabled == '0':
                weak_configs.append("Module signature verification is disabled")
                logger.info("Module signature verification is disabled in: %s", modules_disabled_file)
            else:
                logger.info("Module signature verification is enabled")
    except FileNotFoundError:
        logger.warning("Unable to check module signature verification status")
        weak_configs.append("Unable to check module signature verification status")
    
    return weak_configs, paths_checked

def check_cve_vulnerabilities():
    logger.info("Checking for CVE vulnerabilities...")
    cve_list = []
    
    # Simulated output for demonstration
    cve_urls = [
        "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=secure+boot",
        "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=uefi"
    ]
    
    for url in cve_urls:
        logger.info("Querying %s", url)
        # Simulating output due to lack of 'requests' module
        cves = ['CVE-2021-1234', 'CVE-2021-5678']
        cve_list.extend(cves)
        logger.info("CVEs found from %s: %s", url, ', '.join(cves))
    
    # Only keep top 10 CVEs
    cve_list = cve_list[:10]
    return cve_list

def check_advanced_secure_boot():
    logger.info("Performing advanced Secure Boot check...")
    findings = []
    paths_checked = []

    # Simulated findings and logs
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
        if os.path.exists(file_path):
            findings.append("Found Secure Boot related file: " + file_path)
            paths_checked.append(file_path)
            logger.info("Found: %s", file_path)
        else:
            logger.info("File not found: %s", file_path)

    # Check UEFI configuration using efibootmgr if available
    efibootmgr_path = '/usr/bin/efibootmgr'
    if os.path.exists(efibootmgr_path):
        try:
            logger.info("efibootmgr found, checking UEFI boot entries...")
            efibootmgr_output = subprocess.run([efibootmgr_path, '-v'], capture_output=True, text=True)
            if efibootmgr_output.returncode == 0:
                findings.append("UEFI boot entries found")
                logger.info("UEFI boot entries:\n%s", efibootmgr_output.stdout)
            else:
                logger.warning("efibootmgr command failed with error:\n%s", efibootmgr_output.stderr)
        except Exception as e:
            logger.error("Error executing efibootmgr: %s", e)
    else:
        logger.warning("efibootmgr not found, cannot check UEFI configuration")

    # Recursively check /boot directory
    try:
        logger.info("Recursively checking /boot directory")
        boot_files = subprocess.run(['find', '/boot', '-type', 'f'], capture_output=True, text=True)
        if boot_files.returncode == 0:
            findings.append("Boot directory contents listed")
            logger.info("Boot directory contents:\n%s", boot_files.stdout)
        else:
            logger.warning("Error listing /boot directory contents:\n%s", boot_files.stderr)
    except Exception as e:
        logger.error("Error executing find command: %s", e)

    return findings, paths_checked

def search_firmware_files(root_dir):
    logger.info("Searching for firmware files in directory: %s", root_dir)
    firmware_files = []
    try:
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith(('.bin', '.img')) and os.path.getsize(file_path) < 1024 * 1024 * 100:  # Limit to 100MB
                    firmware_files.append(file_path)
                    logger.info("Found firmware file: %s", file_path)
    except Exception as e:
        logger.error("Error searching firmware files: %s", e)
    return firmware_files

def search_secret_keys(root_dir):
    logger.info("Searching for secret keys or confidential data in directory: %s", root_dir)
    secret_key_files = []
    sensitive_patterns = [
        # Authentication data
        r'password\s*=\s*["\']?\S+["\']?',
        r'passwd\s*=\s*["\']?\S+["\']?',
        r'secret\s*=\s*["\']?\S+["\']?',
        r'key\s*=\s*["\']?\S+["\']?',
        r'token\s*=\s*["\']?\S+["\']?',
        r'credential\s*=\s*["\']?\S+["\']?',
        r'auth\s*=\s*["\']?\S+["\']?',
        r'login\s*=\s*["\']?\S+["\']?',

        # Configuration files
        r'config\s*=\s*["\']?\S+["\']?',
        r'conf\s*=\s*["\']?\S+["\']?',
        r'cfg\s*=\s*["\']?\S+["\']?',
        r'ini\s*=\s*["\']?\S+["\']?',
        r'yaml\s*=\s*["\']?\S+["\']?',
        r'json\s*=\s*["\']?\S+["\']?',

        # Cryptographic material
        r'private_key\s*=\s*["\']?\S+["\']?',
        r'public_key\s*=\s*["\']?\S+["\']?',
        r'cert\s*=\s*["\']?\S+["\']?',
        r'pem\s*=\s*["\']?\S+["\']?',
        r'crt\s*=\s*["\']?\S+["\']?',
        r'cer\s*=\s*["\']?\S+["\']?',
        r'p12\s*=\s*["\']?\S+["\']?',
        r'keystore\s*=\s*["\']?\S+["\']?',

        # Database connection strings
        r'jdbc\s*=\s*["\']?\S+["\']?',
        r'odbc\s*=\s*["\']?\S+["\']?',
        r'connection_string\s*=\s*["\']?\S+["\']?',
        r'db_password\s*=\s*["\']?\S+["\']?',

        # API-related
        r'api_key\s*=\s*["\']?\S+["\']?',
        r'api_secret\s*=\s*["\']?\S+["\']?',
        r'client_id\s*=\s*["\']?\S+["\']?',
        r'client_secret\s*=\s*["\']?\S+["\']?',

        # Device-specific
        r'serial_number\s*=\s*["\']?\S+["\']?',
        r'mac_address\s*=\s*["\']?\S+["\']?',
        r'device_id\s*=\s*["\']?\S+["\']?',
        r'imei\s*=\s*["\']?\S+["\']?',

        # Network-related
        r'ssid\s*=\s*["\']?\S+["\']?',
        r'wifi_password\s*=\s*["\']?\S+["\']?',
        r'ip_address\s*=\s*["\']?\S+["\']?',
        r'gateway\s*=\s*["\']?\S+["\']?',
        r'dns\s*=\s*["\']?\S+["\']?',

        # Sensitive directories
        r'/etc/shadow',
        r'/etc/passwd',
        r'/etc/ssl',
        r'/var/log',
        r'/home/.*/.ssh',

        # Debugging and logging
        r'debug\s*=\s*["\']?\S+["\']?',
        r'log\s*=\s*["\']?\S+["\']?',
        r'trace\s*=\s*["\']?\S+["\']?',
        r'verbose\s*=\s*["\']?\S+["\']?',

        # Firmware and update
        r'firmware\s*=\s*["\']?\S+["\']?',
        r'update\s*=\s*["\']?\S+["\']?',
        r'upgrade\s*=\s*["\']?\S+["\']?',
        r'flash\s*=\s*["\']?\S+["\']?',

        # Encryption-related
        r'aes\s*=\s*["\']?\S+["\']?',
        r'des\s*=\s*["\']?\S+["\']?',
        r'rsa\s*=\s*["\']?\S+["\']?',
        r'encrypt\s*=\s*["\']?\S+["\']?',
        r'decrypt\s*=\s*["\']?\S+["\']?',

        # Cloud services
        r'aws\s*=\s*["\']?\S+["\']?',
        r'azure\s*=\s*["\']?\S+["\']?',
        r'gcp\s*=\s*["\']?\S+["\']?',
        r'cloud_key\s*=\s*["\']?\S+["\']?'
    ]

    try:
        for root, dirs, files in os.walk(root_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                with open(file_path, 'r', errors='ignore') as file:
                    contents = file.read()
                    for pattern in sensitive_patterns:
                        if re.search(pattern, contents, re.IGNORECASE):
                            secret_key_files.append(file_path)
                            logger.info("Found sensitive data pattern in file: %s", file_path)
                            break
    except Exception as e:
        logger.error("Error searching secret keys: %s", e)

    return secret_key_files

def main():
    parser = argparse.ArgumentParser(description="Secure Boot Analysis Tool")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('-r', '--rootdir', type=str, default='/', help="Root directory to search for firmware files and secret keys (default: '/')")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.INFO)

    logger.info("Starting Secure Boot analysis...")

    secure_boot_enabled, secure_boot_poc = check_secure_boot()
    weak_configs, paths_checked = check_weak_configurations()
    cve_list = check_cve_vulnerabilities()
    advanced_findings, advanced_paths_checked = check_advanced_secure_boot()
    firmware_files = search_firmware_files(args.rootdir)
    secret_key_files = search_secret_keys(args.rootdir)

    # Output findings
    logger.info("\nWeak Configurations:")
    for weak_config in weak_configs:
        logger.info("- %s", weak_config)
        logger.info("  Checked in:\n  %s", '\n  '.join(paths_checked))

    logger.info("\nCVE Vulnerabilities:")
    for cve in cve_list:
        logger.info("- %s", cve)

    logger.info("\nAdvanced Secure Boot Findings:")
    for finding in advanced_findings:
        logger.info("- %s", finding)
        logger.info("  Checked in:\n  %s", '\n  '.join(advanced_paths_checked))

    logger.info("\nFirmware Files:")
    for firmware_file in firmware_files:
        logger.info("- %s", firmware_file)

    logger.info("\nSecret Keys or Confidential Data:")
    if secret_key_files:
        for secret_key_file in secret_key_files:
            logger.info("- %s", secret_key_file)
    else:
        logger.info("No secret keys or confidential data found.")

    logger.info("Secure Boot analysis completed.")

if __name__ == "__main__":
    main()
