import sqlite3
import os
import ast
import hashlib
import json
import time

from misc.zigsniff_utilities import report

def create_db(path):
    '''
    Create the database if it does not exist
    '''
    sqlite = os.path.join(path, "zigsniff_database.db")

    #check if file exists if not create it
    if os.path.isfile(sqlite):
        with open(sqlite, 'rb') as file:
            header = file.read(16)
            if header == b'SQLite format 3\000':
                report(f"Will use existing sqlite file: {sqlite}", path)
                return
            else:
                os.remove(sqlite)
                report(f"Existing file {sqlite} was not SQlite. Removed file", path)
                report(f"Will create real SQLite now.", path)
    else:
        report(f"No SQLite file has been found at: {sqlite}", path)
        report(f"Will create it now.", path)

    try:
        connection = sqlite3.connect(sqlite)
        cursor = connection.cursor()

        """
            Create Table for use. add new records here if you need them.
        """
        # TABLES:
        create_device_table = """ CREATE TABLE IF NOT EXISTS devices (
                                        id integer PRIMARY KEY AUTOINCREMENT,
                                        device_mac_address text NOT NULL UNIQUE,
                                        rssi text,
                                        channel int,
                                        device_type text,
                                        manufacturer text,
                                        first_time_seen integer,
                                        last_time_seen integer,
                                        talks_with_mac_list text,
                                        power_source text,
                                        cluster_info text,
                                        capabilities text,
                                        src_net_addresses text,
                                        dst_net_addresses text,
                                        wpan_src_net_addresses text,
                                        wpan_dst_net_addresses text,
                                        protocol_version text,
                                        associated_pan_id text,
                                        sticky_note text,
                                        gps text DEFAULT '0, 0'
                                    );"""

        cursor.execute(create_device_table)

        connection.commit()
        connection.close()
        report(f"Created database: {sqlite}", path)
        return
    except Exception as e:
        report(f"Failed to create database: {sqlite}", path)
        report(f"Error: {e}", path)
        exit()

def nwk_add_dev_to_devices(device_dict, path: str):
    """
    This function takes a :param device_dict:
    example:  {'mac': 'A4:C1:BB:BB:AA:AA', 'broadcast_name': 'Minger_BLABLA_007', 'time': 1668461774, 'gps': (52.123456789, 5.987654321), 'RSSI': '-81'}
    This function then adds all the relevant information depending on certain criteria to the SQLite database.
    """
    sqlite = os.path.join(path, "zigsniff_database.db")
    connection = sqlite3.connect(sqlite)
    cursor = connection.cursor()

    if "nwk_mac_src" in device_dict:
        device_dict["device_manufacturer"] = "unknown"

    manufacturer = "unknown"  # Todo: function needs to be built

    mac = device_dict['nwk_mac_src']
    channel = device_dict['channel']
    dev_time = device_dict['pkt_timestamp']
    device_type = device_dict['device_type']
    nwk_addr_src = str(device_dict['nwk_addr_src'])

    sticky_note = "empty"
    # gps = "{}, {}".format(device_dict['gps'][0], device_dict['gps'][1])
    # rssi = device_dict['rssi']

    # writing data to sqlite database with sanitizing prepared statements
    sql_begin = "BEGIN TRANSACTION;"
    # create query to add device to devices table
    query_add_mac_name = '''INSERT INTO devices ('device_mac_address', 'manufacturer', 'channel', 'device_type', 'sticky_note', 'src_net_addresses')
                    VALUES(:device_mac_address, :manufacturer, :channel, :device_type, :sticky_note, :src_net_addresses);'''
    query_get_id_device = '''SELECT id FROM devices WHERE device_mac_address=? LIMIT 1;'''
    query_add_time = '''UPDATE devices SET first_time_seen=?, last_time_seen=? WHERE id=?;'''
    query_get_last_gps = '''SELECT gps FROM devices WHERE id=? ORDER BY time DESC LIMIT 1;'''
    query_update_time = '''UPDATE devices SET last_time_seen=? WHERE id=?;'''
    query_update_time_gps = '''UPDATE devices SET last_time_seen=?, gps=? WHERE id=?;'''

    if "nwk_addr_src" in device_dict:
        if device_dict["nwk_addr_src"] == '0x0000' or device_dict["nwk_addr_src"] == '0x0001':
            device_type = "Coordinator"
    # create query to add device time gps and rssi to devices table
    try:
        # try and get device id so we know the device exists:
        cursor.execute(query_get_id_device, (mac, ))
        mac_checker = cursor.fetchall()
        if not mac_checker:
            # we do this when the devices does not exists yet
            query_info = (mac, manufacturer, channel, device_type, sticky_note, nwk_addr_src)
            cursor.execute(sql_begin)
            cursor.execute(query_add_mac_name, query_info)
            connection.commit()

            # get device id number from new entry we just created
            cursor.execute(query_get_id_device, (mac,))
            device_id = cursor.fetchall()[0]
            device_id = device_id[0]

            # add time devices table
            cursor.execute(sql_begin)
            cursor.execute(query_add_time, (dev_time, dev_time, device_id))
            connection.commit()
            report(f"adding {mac} {manufacturer} to database....", path)

        else:
            # get device id number from new entry we just created
            cursor.execute(query_get_id_device, (mac,))
            device_id = cursor.fetchall()[0]
            device_id = device_id[0]

            # add time and RSSI to devices table
            cursor.execute(sql_begin)

            if 'gps' in device_dict:
                gps = str(device_dict['gps'])
                cursor.execute(query_update_time_gps, (dev_time, gps, device_id))
            else:
                cursor.execute(query_update_time, (dev_time, device_id))
            connection.commit()
            #report(f"Mac {mac} already in database. updated timestamp....", path)

    # if we get a "UNIQUE constraint failed: devices.mac error" it means the device already exists in the
    # database we only have to update the below-mentioned fields
    # - update last_time_seen
    # except sqlite3.IntegrityError as e:
    except IndexError as e:
        report(f"{type(e)}\n -1---------------------------------------\n", path)
        report(e)
        exit()
    except sqlite3.Error as e:
        report(f"{type(e)}\n -1---------------------------------------\n", path)
        connection.rollback()
        report(e)
        exit()

def match_nwk_addresses(mac, addr_src, assoc_pan_id, addr_dst, path):
    """This function takes a dictionary as input with no mandatory fields. It will go through the dictionary
    looking for fields it recognizes and then puts them in the database accordingly.
    """
    sqlite = os.path.join(path, "zigsniff_database.db")
    connection = sqlite3.connect(sqlite)
    cursor = connection.cursor()

    sql_begin = "BEGIN TRANSACTION;"
    # create query to add device to devices table
    query_add_mac_name = '''INSERT INTO devices ('device_mac_address', 'manufacturer')
                        VALUES(:device_mac_address, :manufacturer);'''
    query_get_id_device = '''SELECT id FROM devices WHERE device_mac_address=? LIMIT 1;'''
    query_add_pan_dst = '''UPDATE devices SET associated_pan_id=? WHERE id=?;'''
    query_get_src_net_address = '''SELECT src_net_addresses FROM devices WHERE id=? LIMIT 1;'''
    query_add_src_net_addr = '''UPDATE devices SET src_net_addresses=? WHERE id=?;'''
    query_get_dst_net_address = '''SELECT dst_net_addresses FROM devices WHERE id=? LIMIT 1;'''
    query_add_dst_net_addr = '''UPDATE devices SET dst_net_addresses=? WHERE id=?;'''

    cursor.execute(query_get_id_device, (mac,))
    mac_checker = cursor.fetchall()
    if mac_checker == []:
        pass
        #print("device not added to the database just yet")
    else:
        # get device id number from new entry we just created
        cursor.execute(query_get_id_device, (mac,))
        device_id = cursor.fetchall()[0]
        device_id = device_id[0]
        # check if assoc_pan_id exists
        try:
            cursor.execute(sql_begin)
            cursor.execute(query_add_pan_dst, (assoc_pan_id, device_id))
            connection.commit()
            #report(f"adding / overwriting pan id {assoc_pan_id} to database for device:  {mac} ....", path)
        except KeyError as e:
            report("Error: " + str(e), path)

        #add device source address
        try:
            src_net_addresses = addr_src
            # fetch the current value of src_net_address
            cursor.execute(query_get_src_net_address, (device_id, ))
            old_src_net_addresses = cursor.fetchall()[0][0]
            if old_src_net_addresses is None:
                cursor.execute(sql_begin)
                cursor.execute(query_add_src_net_addr, (str(src_net_addresses), device_id))
                connection.commit()
                report(f"writing src net address {src_net_addresses} to database for device:  {mac} ....", path)
            else:
                pass
                # old_src_net_addresses = str(old_src_net_addresses)
                # # create a list from the old src net addresses
                # old_src_net_addresses = ast.literal_eval(old_src_net_addresses)
                # if src_net_addresses not in old_src_net_addresses:
                #     old_src_net_addresses.append(src_net_addresses)
                #     cur.execute(sql_begin)
                #     cur.execute(query_add_src_net_addr, (str(old_src_net_addresses), device_id))
                #     sqlite_database.commit()
                #     print(f"writing src net addresses {old_src_net_addresses} to database for device:  {mac} ....")
                # else:
                #     pass
        except KeyError as e:
            report("Error: " + str(e), path)

        #add device destination address
        try:
            dst_net_addresses = addr_dst
            # fetch the current value of src_net_address
            cursor.execute(query_get_dst_net_address, (device_id,))
            old_dst_net_addresses = cursor.fetchall()[0][0]
            if old_dst_net_addresses is None:
                dst_net_addresses_lst = []
                dst_net_addresses_lst.append(dst_net_addresses)
                cursor.execute(sql_begin)
                cursor.execute(query_add_dst_net_addr, (str(dst_net_addresses_lst), device_id))
                connection.commit()
                report(f"writing dst net address {dst_net_addresses_lst} to database for device:  {mac} ....", path)
            else:
                old_dst_net_addresses = str(old_dst_net_addresses)
                # create a list from the old dst net addresses
                old_dst_net_addresses = ast.literal_eval(old_dst_net_addresses)
                if dst_net_addresses not in old_dst_net_addresses:
                    old_dst_net_addresses.append(dst_net_addresses)
                    cursor.execute(sql_begin)
                    cursor.execute(query_add_dst_net_addr, (str(old_dst_net_addresses), device_id))
                    connection.commit()
                    report(f"writing dst net addresses {old_dst_net_addresses} to database for device:  {mac} ....", path)
        except KeyError as e:
            report("Error: " + str(e), path)
            # exit()

def wpan_add_dev_to_devices(device_dict, path):
    """
    This function takes a :param device_dict:
    example:  {'mac': 'A4:C1:BB:BB:AA:AA', 'broadcast_name': 'Minger_BLABLA_007', 'time': 1668461774, 'gps': (52.123456789, 5.987654321), 'RSSI': '-81'}
    This function then adds all the relevant information depending on certain criteria to the SQLite database.
    """

    sqlite = os.path.join(path, "zigsniff_database.db")
    connection = sqlite3.connect(sqlite)
    cursor = connection.cursor()

    # add a manufacturer lookup function

    mac = device_dict['wpan_mac_src']
    manufacturer = "unknown"  # Todo: function needs to be built
    channel = device_dict['channel']
    dev_time = device_dict['pkt_timestamp']
    device_type = device_dict['device_type']
    sticky_note = "empty"
    # gps = "{}, {}".format(device_dict['gps'][0], device_dict['gps'][1])
    # rssi = device_dict['rssi']

    # writing data to sqlite database with sanitizing prepared statements
    sql_begin = "BEGIN TRANSACTION;"
    # create query to add device to devices table
    query_add_mac_name = '''INSERT INTO devices ('device_mac_address', 'manufacturer', 'channel', device_type, 'sticky_note')
                    VALUES(:device_mac_address, :manufacturer, :channel, :device_type, :sticky_note);'''
    query_get_id_device = '''SELECT id FROM devices WHERE device_mac_address=? LIMIT 1;'''
    query_add_time = '''UPDATE devices SET first_time_seen=?, last_time_seen=? WHERE id=?;'''
    query_get_last_gps = '''SELECT gps FROM devices WHERE id=? ORDER BY time DESC LIMIT 1;'''
    query_update_time = '''UPDATE devices SET last_time_seen=? WHERE id=?;'''
    query_update_time_rssi_gps = '''UPDATE devices SET last_time_seen=?, gps=?, rssi=? WHERE id=?;'''


    # create query to add device time gps and rssi to devices table
    try:
        # try and get device id so we know the device exists:
        cursor.execute(query_get_id_device, (mac, ))
        mac_checker = cursor.fetchall()
        if mac_checker == []:
            # we do this when the devices does not exists yet
            query_info = (mac, manufacturer, channel, device_type, sticky_note)
            cursor.execute(sql_begin)
            cursor.execute(query_add_mac_name, query_info)
            connection.commit()

            # get device id number from new entry we just created
            cursor.execute(query_get_id_device, (mac,))
            device_id = cursor.fetchall()[0]
            device_id = device_id[0]

            # add time devices table
            cursor.execute(sql_begin)
            cursor.execute(query_add_time, (dev_time, dev_time, device_id))
            connection.commit()
            report(f"adding {mac} to database....", path)

        else:
            # get device id number from new entry we just created
            cursor.execute(query_get_id_device, (mac,))
            device_id = cursor.fetchall()[0]
            device_id = device_id[0]

            # add time gps and RSSI to devices table
            cursor.execute(sql_begin)
            cursor.execute(query_update_time, (dev_time, device_id))
            connection.commit()
            #report(f"Mac {mac} already in database. updated timestamp....", path)

    # if we get a "UNIQUE constraint failed: devices.mac error" it means the device already exists in the
    # database we only have to update the below-mentioned fields
    # - update last_time_seen
    # except sqlite3.IntegrityError as e:
    except IndexError as e:
        report(f"{type(e)}\n -2---------------------------------------\n", path)
        report(f"Error occured: {e}", path)
    # do a rollback when a sql error happens
        connection.rollback()
        exit()
    except sqlite3.Error as e:
        report(f"{type(e)}\n -2---------------------------------------\n", path)
        report(f"Error occured: {e}", path)
        connection.rollback()
        exit()

def match_wpan_addresses(addr_wpan_src, assoc_pan_id, addr_wpan_dst, path):
    """This function takes a dictionary as input with no mandatory fields. It will go through the dictionary
    looking for fields it recognizes and then puts them in the database accordingly.
    """

    sqlite = os.path.join(path, "zigsniff_database.db")
    connection = sqlite3.connect(sqlite)
    cursor = connection.cursor()

    sql_begin = "BEGIN TRANSACTION;"
    # create query to add device to devices table
    query_get_id_device = '''SELECT id FROM devices WHERE src_net_addresses=? LIMIT 1;'''
    query_get_wpan_dst_net_address = '''SELECT wpan_dst_net_addresses FROM devices WHERE id=? LIMIT 1;'''
    query_add_wpan_dst_net_addr = '''UPDATE devices SET wpan_dst_net_addresses=? WHERE id=?;'''
    query_add_pan_dst = '''UPDATE devices SET associated_pan_id=? WHERE id=?;'''

    cursor.execute(query_get_id_device, (addr_wpan_src,))
    mac_checker = cursor.fetchall()
    if mac_checker == []:
        pass
        #print("device not added to the database just yet")
    else:
        # get device id number from new entry we just created
        cursor.execute(query_get_id_device, (addr_wpan_src,))
        device_id = cursor.fetchall()[0]
        device_id = device_id[0]
        try:
            cursor.execute(sql_begin)
            cursor.execute(query_add_pan_dst, (assoc_pan_id, device_id))
            connection.commit()
            #report(f"adding / overwriting pan id {assoc_pan_id} to database for device:  {addr_wpan_src} ....", path)
        except KeyError as e:
            report("Error: " + str(e), path)
            # exit()
            pass

        #add device destination address
        try:
            wpan_dst_net_addresses = addr_wpan_dst
            # fetch the current value of src_net_address
            cursor.execute(query_get_wpan_dst_net_address, (device_id,))
            old_wpan_dst_net_addresses = cursor.fetchall()[0][0]
            if old_wpan_dst_net_addresses is None:
                wpan_dst_net_addresses_lst = []
                wpan_dst_net_addresses_lst.append(wpan_dst_net_addresses)
                cursor.execute(sql_begin)
                cursor.execute(query_add_wpan_dst_net_addr, (str(wpan_dst_net_addresses_lst), device_id))
                connection.commit()
                report(f"writing wpan dst net address {wpan_dst_net_addresses_lst} to database for device:  {addr_wpan_src} ....", path)
            else:
                old_wpan_dst_net_addresses = str(old_wpan_dst_net_addresses)
                # create a list from the old dst net addresses
                old_wpan_dst_net_addresses = ast.literal_eval(old_wpan_dst_net_addresses)
                if wpan_dst_net_addresses not in old_wpan_dst_net_addresses:
                    old_wpan_dst_net_addresses.append(wpan_dst_net_addresses)
                    cursor.execute(sql_begin)
                    cursor.execute(query_add_wpan_dst_net_addr, (str(old_wpan_dst_net_addresses), device_id))
                    connection.commit()
                    report(f"writing wpan dst net addresses {old_wpan_dst_net_addresses} to database for device:  {addr_wpan_src} ....", path)
        except KeyError as e:
            report("Error: " + str(e), path)
            # exit()

def parse_the_rest(device_dict: dict, path):

    sqlite = os.path.join(path, "zigsniff_database.db")
    connection = sqlite3.connect(sqlite)
    cursor = connection.cursor()

    sql_begin = "BEGIN TRANSACTION;"
    # create query to add device to devices table
    query_get_id_device = '''SELECT id FROM devices WHERE src_net_addresses=? LIMIT 1;'''
    query_get_device_type = '''SELECT device_type FROM devices WHERE id=? LIMIT 1;'''
    query_get_talks_with_mac_list = '''SELECT talks_with_mac_list FROM devices WHERE id=? LIMIT 1;'''
    query_get_capabilities_dict = '''SELECT capabilities FROM devices WHERE id=? LIMIT 1;'''
    query_get_cluster_dict = '''SELECT cluster_info FROM devices WHERE id=? LIMIT 1;'''
    query_add_device_type = '''UPDATE devices SET device_type=?, last_time_seen=? WHERE id=?;'''
    query_add_talks_with_mac_list = '''UPDATE devices SET talks_with_mac_list=?, last_time_seen=? WHERE id=?;'''
    query_add_capabilities_dict = '''UPDATE devices SET capabilities=?, last_time_seen=? WHERE id=?;'''
    query_add_cluster_dict = '''UPDATE devices SET cluster_info=?, last_time_seen=? WHERE id=?;'''
    query_add_rssi = '''UPDATE devices SET rssi=?, last_time_seen=? WHERE id=?;'''

    nwk_addr_src = str(device_dict['nwk_addr_src'])
    cursor.execute(query_get_id_device, (nwk_addr_src,))
    checker = cursor.fetchall()
    dev_time = device_dict['pkt_timestamp']

    if checker == []:
        pass
        report(f"device with address {nwk_addr_src} not added to the database just yet", path)
    else:
        # get device id number from new entry we just created
        cursor.execute(query_get_id_device, (nwk_addr_src,))
        device_id = cursor.fetchall()[0]
        device_id = device_id[0]
        # check if assoc_pan_id exists
        # Determine device_type
        try:
            if 'device_type' in device_dict:
                device_type = device_dict['device_type']
                # fetch the current value of src_net_addresses
                cursor.execute(query_get_device_type, (device_id,))
                old_device_type = cursor.fetchall()[0][0]
                if old_device_type == "unknown" and device_type != "unknown":
                    cursor.execute(sql_begin)
                    cursor.execute(query_add_device_type, (device_type, dev_time, device_id))
                    connection.commit()
                    report(f"writing new device type {device_type} to database for device:  {nwk_addr_src} ....", path)
                else:
                    pass
        except KeyError as e:
            report("Error: " + str(e), path)
            # exit()

        # talks with mac list filling and adding
        try:
            if 'nwk_mac_dst' in device_dict:
                talks_with_mac_list_entry = device_dict['nwk_mac_dst']
                # fetch the current value of talks_with_mac_list
                cursor.execute(query_get_talks_with_mac_list, (device_id, ))
                old_talks_with_mac_list = cursor.fetchall()[0][0]
                if old_talks_with_mac_list is None:
                    talks_with_mac_list = []
                    talks_with_mac_list.append(talks_with_mac_list_entry)
                    cursor.execute(sql_begin)
                    cursor.execute(query_add_talks_with_mac_list, (str(talks_with_mac_list), dev_time, device_id))
                    connection.commit()
                    #zigsniff_utilities.report_system(f"writing talks_with_mac_list {talks_with_mac_list} to database for device:  {nwk_addr_src} ....")
                else:
                    old_talks_with_mac_list = str(old_talks_with_mac_list)
                    # create a list from the old mac addresses
                    old_talks_with_mac_list = ast.literal_eval(old_talks_with_mac_list)
                    if talks_with_mac_list_entry not in old_talks_with_mac_list:
                        old_talks_with_mac_list.append(talks_with_mac_list_entry)
                        cursor.execute(sql_begin)
                        cursor.execute(query_add_talks_with_mac_list, (str(old_talks_with_mac_list), dev_time, device_id))
                        connection.commit()
                        #zigsniff_utilities.report_system(f"writing talks_with_mac_list {old_talks_with_mac_list} to database for device:  {nwk_addr_src} ....")
                    else:
                        pass
        except KeyError as e:
            report("Error: " + str(e), path)
            exit()
            pass
        try:
            key_1 = device_dict['network_key']
        except KeyError as e:
            pass
        try:
            key_2 = device_dict['pan_key']
        except KeyError as e:
            pass
        try:
            if 'zdp_node_lqi' in device_dict:
                lqi = device_dict['zdp_node_lqi']
                cursor.execute(sql_begin)
                cursor.execute(query_add_rssi, (lqi, dev_time, device_id))
                connection.commit()
                #zigsniff_utilities.report_system(f"writing rssi {lqi} to database for device:  {nwk_addr_src} ....")
        except KeyError as e:
            report("Error: " + str(e), path)
            exit()
            pass

        # determine and add/update device capabilities
        try:
            capability = {}
            #ZCL Based entries
            if "command_temperature_measured" in device_dict:
                capability["Measure Temperature"] = float(device_dict["command_temperature_measured"])
            if "command_humidity_measured" in device_dict:
                capability["Measure Humidity"] = float(device_dict["command_humidity_measured"])

            #Battery
            if "command_battery_percentage" in device_dict:
                capability["Battery Percentage"] = float(device_dict["command_battery_percentage"])
            if "command_battery_voltage" in device_dict:
                capability["Battery Voltage"] = float(device_dict["command_battery_voltage"])
            if "command_battery_status" in device_dict:
                value = device_dict["command_battery_status"]
                if value == "0":
                    value = "Bad"
                elif value == "1":
                    value = "Ok"
                capability["Battery Status"] = value
            if "command_pressure_level_detail" in device_dict:
                capability["Air Pressure Level Detection"] = float(device_dict["command_pressure_level_detail"])

            #light detection
            if "command_illummeas_value" in device_dict:
                capability["Illumination Detection"] = float(device_dict["command_illummeas_value"])

            #Lamps
            if "command_color_temperature" in device_dict:
                capability["Light Color Temperature"] = int(device_dict["command_color_temperature"])
            if "command_color_attr_color_x" in device_dict:
                capability["Light Color Control X"] = int(device_dict["command_color_attr_color_x"])
            if "command_color_attr_color_y" in device_dict:
                capability["Light Color Control Y"] = int(device_dict["command_color_attr_color_y"])
            if "command_color_control_id" in device_dict:
                capability["Light Color Control ID"] = str(device_dict["command_color_control_id"])
            if "command_onoff_cmd_id" in device_dict:
                capability["Light Send On/Off Command id"] = str(device_dict["command_onoff_cmd_id"])
            if "zdp_node_manufacturer" in device_dict:
                capability["Device Manufacturer"] = str(device_dict["zdp_node_manufacturer"])

            #Switches
            if "command_onoff_attr_onoff" in device_dict:
                value = device_dict["command_onoff_attr_onoff"]
                if value == "0x00":
                    value = "Off"
                elif value == "0x01":
                    value = "On"
                else:
                    value = "unknown"
                capability["On/Off Switch"] = value

            #OTA
            if "ota_manufacturer_code" in device_dict:
                capability["OTA Manufacturer code"] = device_dict["ota_manufacturer_code"]
            if "ota_hardware_version" in device_dict:
                capability["OTA Hardware Version"] = device_dict["ota_hardware_version"]
            if "ota_image_type" in device_dict:
                capability["OTA Image Type"] = device_dict["ota_image_type"]
            if "ota_status" in device_dict:
                capability["OTA Status"] = device_dict["ota_status"]
            if "ota_file_version" in device_dict:
                capability["OTA File Version"] = device_dict["ota_file_version"]

            #motion sensors
            if "command_sensing_occupancy_occupied" in device_dict:
                value = device_dict["command_sensing_occupancy_occupied"]
                if value == 0:
                    value = "Clear"
                elif value == 1:
                    value = "Occupied"
                else:
                    pass
                capability["Occupancy Detection"] = value

            # fetch the current dict of capabilites
            cursor.execute(query_get_capabilities_dict, (device_id,))
            capabilities_dict = cursor.fetchall()[0][0]
            if capabilities_dict is None:
                capabilities_dict = {}
                if len(capability) != 0:
                    capabilities_dict.update(capability)
                capabilities_dict = str(capabilities_dict)
            elif capabilities_dict is not None:
                capabilities_dict = eval(capabilities_dict)
                if len(capability) != 0:
                    capabilities_dict.update(capability)

            capabilities_dict = str(capabilities_dict)
            if capabilities_dict is not None and len(capabilities_dict) != 0 and capabilities_dict != "{}":
                cursor.execute(sql_begin)
                cursor.execute(query_add_capabilities_dict, (capabilities_dict, dev_time, device_id))
                connection.commit()
                report(f"writing capabilities dictionary to database for device:  {nwk_addr_src} ....", path)
            else:
                pass
                #zigsniff_utilities.report_system(f"no capabilities added to database for packet {device_dict['pkt_number']} device:  {nwk_addr_src} ....")

        except KeyError as e:
            report("-sql-parser-1---------------------------------------------------", path)
            report(device_dict, path)
            report(f"Error: {e}", path)
            exit()

        try:

            # APS
            # Clusters cluster_info
            cluster = {}
            if "cluster" in device_dict:
                pkt_cluster = device_dict["cluster"]
                # 0 - 100
                if pkt_cluster == "0x0000":
                    cluster["Cluster_Basic"] = "Device communicates basic attributes and configurations"
                if pkt_cluster == "0x0001":
                    cluster["Cluster_Power_Configuration"] = "Device is battery powered"
                elif pkt_cluster == "0x0005":
                    cluster["Cluster_Scenes"] = str("Device has pre/user -defined scenes")
                elif pkt_cluster == "0x0006":
                    cluster["Cluster_switch-button"] = str("On-Off")
                    if "dst_enpoint" not in device_dict:
                        device_dict["dst_enpoint"] = "unknown"
                    cluster["Endpoint-Button/Endpoint_id_" + str(device_dict["dst_enpoint"])] = str(device_dict["dst_enpoint"])
                elif pkt_cluster == "0x0008":
                    cluster["Cluster_Level_Control"] = "Unknown"

                # 0x0013 = Device Announcement
                elif pkt_cluster == "0x0012":
                    #figure out what to add
                    cluster["Cluster_Multistate_input"] = str("Multistate_input")
                elif pkt_cluster == "0x0013":
                    #figure out what to add
                    cluster["Cluster_Multistate_output"] = str("Multistate_output")

                elif pkt_cluster == "0x0019":
                    cluster["Cluster_OTA_Upgrade"] = str("Supports OTA firmware upgrade/downgrade/mod")

                # 0x0031 = LQI Request
                # 0x0032 = MGMT Routing

                elif pkt_cluster == "0x0036":
                    cluster["Cluster_Network_Join_Enabled"] = device_dict["zdp_node_duration"]
                elif pkt_cluster == "0x0101":
                    cluster["Cluster_Status"] = "Door Lock (vibr det)"
                elif pkt_cluster == "0x0300":
                    cluster["Cluster_Color_Ctrl"] = "Manages colors"
                elif pkt_cluster == "0x0400":
                    cluster["Cluster_Illuminance_Measurement"] = "Measures light"
                elif pkt_cluster == "0x0402":
                    cluster["Cluster_Temperature_Measurement"] = "Measures Temperatures"
                elif pkt_cluster == "0x0403":
                    cluster["Cluster_Pressure_Measurement"] = "Measures pressure (pro Air)"
                elif pkt_cluster == "0x0405":
                    cluster["Cluster_Humidity_Measurement"] = "Measures air humidity"
                elif pkt_cluster == "0x0406":
                    cluster["Cluster_Occupancy_Detection"] = "Measure movement/occupancy"
                elif pkt_cluster == "0x0500":
                    cluster["Cluster_Alarm_Zone"] = "Intruder Alarm Zone"
                elif pkt_cluster == "0x0702":
                    cluster["Cluster_Simple_Metering"] = "Measures stuff (electric, gas, water or thermal)"
                # 8000
                elif pkt_cluster == "0x8000":
                    if "zdp_node_status" in device_dict:
                        status = device_dict["zdp_node_status"]
                        if status == 0:
                            cluster["Cluster_Network_Address_Response"] = "Success"
                        elif status == 1:
                            cluster["Cluster_Network_Address_Response"] = "Failed"
                    else:
                        cluster["Cluster_" + pkt_cluster] = "Network Address Response"
                elif pkt_cluster == "0x8006":
                    cluster["Cluster_Status"] = "Group Cluster Member"
                elif pkt_cluster == "0x0b04":
                    cluster["Cluster_Electrical_Measurement"] = "Measures its or a devices electrical usage"
                elif pkt_cluster == "0x000a":
                    cluster["Cluster_Time"] = "Syncs time with RTC/Server"
                else:
                    cluster["Cluster_" + pkt_cluster] = pkt_cluster

                #clusters
                cursor.execute(query_get_cluster_dict, (device_id,))
                cluster_dict = cursor.fetchall()[0][0]
                if cluster_dict is None:
                    cluster_dict = {}
                    if len(cluster) != 0:
                        cluster_dict.update(cluster)
                    cluster_dict = str(cluster_dict)
                elif cluster_dict is not None:
                    cluster_dict = eval(cluster_dict)
                    if len(cluster_dict) != 0:
                        cluster_dict.update(cluster_dict)

                cluster_dict = str(cluster_dict)
                if cluster_dict is not None and len(cluster_dict) != 0 and cluster_dict != "{}":
                    cursor.execute(sql_begin)
                    cursor.execute(query_add_cluster_dict, (cluster_dict, dev_time, device_id))
                    connection.commit()
                    report(f"writing cluster dictionary to database for device:  {nwk_addr_src} ....", path)
                else:
                    pass
                    #zigsniff_utilities.report_system(f"no cluster added to database for packet {device_dict['pkt_number']} device:  {nwk_addr_src} ....")


        except KeyError as e:
            report("-sql-parser-2--------------------------------------------------", path)
            report(device_dict, path)
            report(f"Error: {e}", path)
            exit()

def get_sticky_note(nwk_addr_src, path):
    '''
    This function helps maintain the last setting of a device so when multiple packets report a status of a device only 1 message is generated.
    :param nwk_addr_src:
    :return:
    '''
    query_get_id_device = '''SELECT id FROM devices WHERE src_net_addresses=? LIMIT 1;'''
    query_get_sticky_note_device = '''SELECT sticky_note FROM devices WHERE id=? LIMIT 1;'''

    try:
        sqlite = os.path.join(path, "zigsniff_database.db")
        connection = sqlite3.connect(sqlite)
        cursor = connection.cursor()

        # Execute the query to get the device ID.
        cursor.execute(query_get_id_device, (nwk_addr_src,)) # Get the device id
        device_id_result = cursor.fetchall()

        if not device_id_result:
            return "Error"  # Handle this case as needed.

        device_id = device_id_result[0][0]

        # Execute the query to get the sticky note.
        cursor.execute(query_get_sticky_note_device, (device_id,))
        sticky_note_result = cursor.fetchall()

        if not sticky_note_result:
            return "Error"  # Handle this case as needed.

        sticky_note = sticky_note_result[0][0]

        if sticky_note is not None:
            if sticky_note == "empty":
                sticky_note = "{}"
            return ast.literal_eval(sticky_note)
        else:
            return "Error"
    except Exception as e:
        report("Error occurred " + nwk_addr_src + " with sticky_note read " + str(e), path)
        return "Error"

def change_sticky_note(nwk_addr_src, value, path):
    '''
    We update the value of the specific device in case it changes and we can genereate a .zmessage file.
    :param nwk_addr_src:
    :param value:
    :return:
    '''
    query_get_id_device = '''SELECT id FROM devices WHERE src_net_addresses=? LIMIT 1;'''
    query_change_sticky_note = '''UPDATE devices SET sticky_note=? WHERE id=?;'''

    try:
        sqlite = os.path.join(path, "zigsniff_database.db")
        connection = sqlite3.connect(sqlite)
        cursor = connection.cursor()

        cursor.execute(query_get_id_device, (nwk_addr_src,))
        device_id = cursor.fetchall()[0]
        device_id = device_id[0]

        cursor.execute(query_change_sticky_note, (str(value), device_id,))
        connection.commit()
        return 0
    except Exception as e:
        report("Error occurred " + nwk_addr_src + " with sticky_note change " + str(e), path)
        return 1

def zigsniff_reporter(path: str, report_period: int):
    sqlite = os.path.join(path, "zigsniff_database.db")

    report("Running report", path)
    query_get_device_dict = '''SELECT * FROM devices WHERE last_time_seen>?;'''

    prev_timestamp = time.time() - report_period

    try:
        connection = sqlite3.connect(sqlite)
        cursor = connection.cursor()

        cursor.execute(query_get_device_dict, (prev_timestamp,))
        results = cursor.fetchall()
        column_names = [desc[0] for desc in cursor.description]
    except Exception as e:
        report("#" * 30, path)
        report(e, path)
        report("#" * 30, path)
        return 1

    device_list = []
    for row in results:
        device_dict = dict(zip(column_names, row))
        device_list.append(device_dict)

    for device in device_list:
        try:
            md5_hash = hashlib.md5()
            md5_hash.update(str(str(time.time()) + str(device)).encode('utf-8'))
            output_file = os.path.join(path, f"{md5_hash.hexdigest()}.zigsniff")
            file_handle = open(output_file, "a")
            file_handle.write(json.dumps(device))
            file_handle.close()
        except Exception as e:
            report("#" * 30, path)
            report("Error: Writing a message", path)
            report(e, path)
            report("#" * 30, path)
            return 1
    return 0