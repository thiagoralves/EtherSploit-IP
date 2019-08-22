# EtherSploit/IP
EtherSploit/IP is an interactive shell with a bunch of helpful commands to exploit EtherNet/IP vulnerabilities. More specifically, this tool explores the way Rockwell Micrologix PLCs communicate using EtherNet/IP and abuse some of its original functionalities. Here is a list of the commands currently implemented on EtherSploit/IP:

```
EtherSploit/IP> help

Commands available:
  help                 Show available commands
  exit                 Exit from current mode
  history              Show a list of previously run commands
  connect              Connect to an EtherNet/IP Device
  get_device_info      Retrieve device information
  start_plc            Places PLC in RUN mode
  stop_plc             Places PLC in PROG mode
  send_raw_pccc        Send raw PCCC messages to a connected device
  read_password        Retrieve protection password from PLC
  write_password       Overwrite protection password on PLC
  change_ip            Change PLC's IP Address
  wipe_memory          Erase PLC ladder logic files
  reboot_plc           Send an SNMP packet that reboots the PLC
  enable_protocols     Enable SNMP, Modbus and HTTP
  force_cpu_fault      Generate a CPU fault by triggering HSC error and auto-start bits
  clear_cpu_fault      Clear all CPU faults
  kill_plc             Transforms PLC into a brick
  ```
  
  The vulnerabilities explored by EtherSploit/IP affects the MicroLogix PLC family. These devices are used worldwide by organizations in the critical infrastructure, food and agriculture, and water and wastewater sectors for controlling processes. EtherSploit/IP vulnerabilities affect all firmware versions, up to the latest one (FRN21.05). The vulnerabilities are:
  1. Remotely start/stop the PLC
  2. Read PLC protection password
  3. Overwrite protection password (even if password is encrypted)
  4. Change device's IP address remotely
  5. Erase device's memory
  6. Reboot device remotely
  7. Enable all communication protocols (there are known vulnerabilities associated with other protocols. As a mitigation, all protocols are disabled by default on the latest firmware. This command turns them back on)
  8. Force device into FAULT state
  9. Crash PLC using a bad Modbus packet (This one doesn't work anymore on the latest firmware. I presented it last year on DEFCON 26 and Rockwell fixed it. Anyway, I though it would be cool to include it on EtherSploit/IP as well)

NOTE: On the last firmware, Rockwell introduced a new CPU mode called "Enhanced Password Security". When this mode is enabled and the device is protected with a password, most exploits stop working because this new mode requires password authentication for every protected memory read/write. That being said, it is important to note that the "Enhanced Password Security" mode is not enabled by default, users must enable it manually, which means that PLCs can be unprotected even with the latest firmware version.

## Compiling
To compile:
```
gcc *.c -o ethersploit -lcrypt
```
