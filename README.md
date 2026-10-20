# Network Port Scanner

A Python-based cybersecurity tool for scanning TCP ports, identifying accessible services, and collecting basic service information in an authorized lab environment.

## Project Overview

This project demonstrates practical networking and cybersecurity concepts using Python socket programming and concurrent connections. It was developed and tested in a virtual lab with Kali Linux as the scanning machine and Ubuntu Server as the target.

## Features

- Scan a user-defined range of TCP ports
- Validate target IP addresses and scan parameters
- Use concurrent connections to improve scanning efficiency
- Identify common services on open ports
- Perform basic banner grabbing
- Detect HTTP services and retrieve basic response information
- Display scan statistics
- Save scan results to a text report
- Compare results with Nmap

## Technologies Used

- Python 3
- Kali Linux
- Ubuntu Server
- Oracle VirtualBox
- Nmap

## Project Files

- `scanner_final.py` — main port scanner script
- `PROJECT_DOCUMENTATION.md` — detailed project documentation

## Getting Started

1. Install Python 3 on your system.
2. Download or clone this repository.
3. Open a terminal in the project directory.
4. Run the scanner's help command to review its supported options:

   ```bash
   python scanner_final.py --help
   ```

5. Run scans only against systems you own or have explicit permission to test.

Refer to `PROJECT_DOCUMENTATION.md` for further details.

## Lab Environment

The scanner was tested in an authorized virtual lab using Kali Linux and Ubuntu Server virtual machines.

## Responsible Use

This tool is intended for learning, authorized security testing, and lab use. Only scan systems and networks for which you have explicit authorization.


