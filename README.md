# Build Gates - The Automated Windows Build Audit

**A lightweight PowerShell script for performing an automated security and configuration review of a Windows build.**

---

## Overview

This repository contains a PowerShell script that performs a collection of system checks useful for a quick security / build audit on Windows machines. It gathers OS and hardware information, account and group policies, security-related settings (BitLocker, Secure Boot, LSA protections, Windows Defender), process mitigations (DEP/ASLR), and other platform hardening checks. It also attempts some manufacturer-specific BIOS checks for Lenovo systems.

> **Note:** This tool is intended for fast, informative inspection and should **not** replace a formal security assessment. Always review results manually and test in a controlled environment before using in production.

---

## Features

- Collects `systeminfo`, installed hotfixes and OS metadata
- Reports applied Group Policy Objects (via `gpresult /R`)
- Checks common account and password policies (`net accounts`)
- Enumerates user groups and privileges; flags potentially sensitive memberships/privileges
- Detects enabled local Administrator/Guest accounts
- Reports cached logon count and LSA (`RunAsPPL`) protection
- Checks Secure Boot and BitLocker status (when run as Administrator)
- Performs Windows Defender status check (real-time and tamper protection)
- Reads DEP/ASLR and other process mitigation settings
- Checks Kernel DMA Protection and Kernel Shadow Stacks if available
- Searches user Desktop for likely cleartext sensitive files and saves findings to `cleartextpw.txt` if found
- Lenovo BIOS password/UEFI checks (Lenovo-only via WMI)
- Aggregates warnings and prints an audit summary

---

## Requirements

- Windows 10 / Windows 11 (most checks should work on recent Windows Server editions too)
- PowerShell (Windows PowerShell / PowerShell Core may work but tested with Windows PowerShell)
- Run as **Administrator** to enable hardware/firmware checks (Secure Boot, BitLocker, BIOS queries)
- Execution policy: recommended to run with `-ExecutionPolicy Bypass` when launching from command line

---

## Warnings & Safety

- **Run with caution.** The script reads registry keys, WMI data, and runs administrative utilities. Do not run on systems you do not own or have permission to inspect.
- The script attempts to identify cleartext sensitive data using a simple keyword search. This is a heuristic and can produce false positives/negatives.
- BIOS checks are implemented only for Lenovo devices (WMI class used). Other manufacturers will be skipped.
- Some commands rely on Windows features and modules (e.g., `Get-MpComputerStatus`, `Confirm-SecureBootUEFI`, `Get-LocalUser`). If a command/module is unavailable the script will output an error for that section and continue.
- The script saves detected cleartext findings to `cleartextpw.txt` in the current working directory — treat that file as sensitive and remove it after review.

---

## Limitations & Known Issues

- **Lenovo-only BIOS checks.** Manufacturer-specific BIOS queries are implemented for Lenovo. Other vendors: check BIOS/UEFI manually.
- Some checks require administrative privileges — if not run elevated, various checks are skipped and warnings will indicate this.
- `Get-WmiObject Win32_Product` is used to list installed software in the script; be aware that calling this class can trigger an inventory check and is slow. You may wish to replace it with registry-based enumerations (HKLM:\Software and HKLM:\Software\WOW6432Node) for production use.
- The hotfix extraction from `systeminfo` is heuristic and may not be perfect on every localized Windows build.

---

## Recommendations

- Always run in an elevated session when you need complete results.
- Prefer removing or securely handling `cleartextpw.txt` after reviewing findings.
- Consider replacing `Win32_Product` queries with registry-based enumerations for performance and side-effect reduction.

---

## Changelog

- **2025-10-07** — Initial public release (script and README)

---

