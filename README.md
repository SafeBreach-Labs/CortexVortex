# CortexVortex

CortexVortex is a command-line tool for managing Cortex XDR, providing functionalities to modify Cortex XDR settings such as changing rules, restarting the XDR process, disabling the local analysis engine, and inserting any python code to run within cortex-xdr-payload.exe process.

## Notes:
The dse_rules_config.lua is the primary file for behavioral rules. While this file provides numerous behavior rule detections that can be turned off, it doesn't cover every scenario. There is also local analysis. For example, if you want to run Mimikatz on a machine with a vulnerable Cortex version, you'll need to disable local analysis along with removing the Mimikatz behavioral rules.

So, you would need to run these two commands:

CortexVortex change_rules --rule_name mimikatz --new_value allow
CortexVortex local_analysis disable
   


## Usage

```bash
CortexVortex change_rules --rules_file <rules_file> --rule_name <rule_name_to_change> --new_value <allow, block, internal>
CortexVortex local_analysis <enable, disable>
CortexVortex restart_xdr
CortexVortex run_as_malware <path_to_python_file>
```

### Available Commands

- `change_rules`: Change Cortex XDR rules.
- `local_analysis`: Disable/Enable XDR's local analysis.
- `restart_xdr`: Restart Cortex XDR process.
- `run_as_malware`: Allows any given python code to run within cortex-xdr-payload process.

## Examples

```bash
# Change rules
CortexVortex change_rules --rules_file dse_rules.json --rule_name mimikatz --new_value allow

# Disable local analysis
CortexVortex local_analysis disable

# Restart XDR
CortexVortex restart_xdr

# Run As Malware
CortexVortex run_as_malware my_malicous_python.py

```

## Author - Shmuel Cohen
* LinkedIn - [Shmuel Cohen](https://www.linkedin.com/in/the-shmuel-cohen/)
* Twitter - [@_BinWalker_](https://twitter.com/_BinWalker_)
