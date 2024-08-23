import binascii
import os
import time
import json
import hashlib
import gpsd

def report(text: str, path: str):
    try:
        path = os.path.join(path, "zigsniff_logging.log")
        print(text)
        file_handle = open(path, "a")
        file_handle.write(f"{time.strftime('%Y-%m-%d_%H-%M-%S')}\t-\t{text}\n")
        file_handle.close()
    except:
        print(f"Error: Writing to sensor system log file {path}")
        exit() # no logfile means kill the program!

def write_zigsniff_message(dict, path):
    try:
        md5_hash = hashlib.md5()
        md5_hash.update(str(dict).encode('utf-8'))
        message_file_name = f"zigsniff_{md5_hash.hexdigest()}.zmessage"
        message_path = os.path.join(path, message_file_name)
        file_handle = open(message_path, "a")
        file_handle.write(json.dumps(dict))
        file_handle.close()
    except Exception as e:
        report(f"Error: Writing a zmessage: {e}", path)
        exit()

def create_work_directory(path: str):
    if os.path.isdir(path):
        report(f"work directory already exists: {path}", path)
        return
    elif os.path.isfile(path):
        print(f"path given is a file: {path}")
        print(f"path given must be existing folder or not exist")
        exit()
    else:
        try:
            os.makedirs(path)
            report(f"Created work directory: {path}", path)
            return
        except Exception as e:
            print(f"Could not create work folder: {e}")
            exit()

def key_management_add_key(key, path):
    #this whole thing needs to be tested!
    found = False
    with open("zigbee_pc_keys", 'r') as file:
        for line in file:
            if key in line:
                found = True
                break

    if not found:

        key_bytes = bytes.fromhex(key.replace(":", ""))
        key_crc = binascii.crc32(key_bytes)
        key_name = str(key_crc)

        with open("zigbee_pc_keys", 'a') as file:
            file.write(f'"{key}","Normal","{key_name}"\n')
            report(f'The string "{key}" has been added to persistent file.', path)

        # with open("~/.config/wireshark/zigbee_pc_keys", 'a') as file:
        #     file.write(f'"{key}","Normal","{key_name}"\n')
        #     report(f'The string "{key}" has been added to volatile file.', path)

    else:
        report(f'The string "{key}" already exists in the persistent file.', path)

def mac_vendor_lookup(mac_64bit: str):
    pass

def get_gps_loc():
    try:
        gpsd.connect(host="127.0.0.1", port=2947)
        location = gpsd.get_current()
        lati = location.lat
        longi = location.lon
        if lati != 0.0 and longi != 0.0:
            current = (longi, lati)
            return current
        else:
            return None
    except Exception as e:
        return None
