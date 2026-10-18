# Network Port Scanner

## 1. Project Overview

The Network Port Scanner is a Python-based cybersecurity tool designed to identify open TCP ports and

 determine the services running on those ports. The scanner was developed and tested in an authorized virtual

 lab environment using Kali Linux as the scanning machine and an Ubuntu Server virtual machine as the target.

The tool uses concurrent TCP connections to scan a user-defined range of ports. When an open port is detected, 

the scanner attempts to identify the associated service and retrieve basic service information through banner grabbing and HTTP detection.

The project demonstrates practical cybersecurity concepts including TCP networking, socket programming, port scanning, service 

identification, concurrency, input validation, error handling, and security testing within an authorized environment.


## 2. Objectives

The main objectives of this project were:

- Develop a functional TCP network port scanner using Python.
- Allow users to specify a target IP address and port range.
- Validate user input and handle invalid IP addresses, port ranges, and timeout values.
- Use concurrent scanning to improve scanning efficiency.
- Identify common services associated with open TCP ports.
- Retrieve basic service banners from accessible services.
- Detect HTTP services and retrieve basic HTTP response information.
- Provide a summary of discovered services and scan statistics.
- Allow scan results to be saved to a text report.
- Test and validate the scanner against an authorized Ubuntu Server virtual machine.
- Compare the scanner's results with Nmap as a reference tool.


## 3. Technologies Used

### Programming Language

- Python 3.13.14

### Operating System

- Kali Linux — used as the scanning machine.
- Ubuntu Server — used as the authorized target machine.

### Virtualization

- Oracle VirtualBox — used to run the virtual lab machines.

### Python Libraries and Modules

- `socket` — used to create TCP connections and communicate with network services.
- `concurrent.futures` — used to perform concurrent port scanning with multiple threads.
- `ipaddress` — used to validate target IP addresses.
- `argparse` — used to provide command-line arguments and options.
- `time` — used to measure scan duration.

### Security and Networking Tools

- Nmap — used as a reference tool to validate the custom scanner's results.

### Output

- Plain-text report files — used to store scan results, service information, and scan statistics.
