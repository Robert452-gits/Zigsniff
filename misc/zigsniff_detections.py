from misc.zigsniff_utilities import report, write_zigsniff_message, key_management_add_key
from misc.zigsniff_sqlite import get_sticky_note, change_sticky_note

def zigbee_detections(dissector, path):
    try:

        #config = zigsniff_config_class.config()

        zigbee_message = {}
        zigbee_message['pan_id'] = dissector['pan_dst']
        zigbee_message['pkt_number'] = dissector['pkt_number']
        zigbee_message["timestamp"] = dissector["pkt_timestamp"]
        zigbee_message["pcap"] = dissector["pcap"]
        zigbee_message["device_channel"] = dissector["channel"]
        zigbee_message["device_address"] = dissector["nwk_addr_src"]

        if "link_key_secret" in dissector:
            # Network key discovered message.
            detection = "Network Transport Key has been found"
            zigbee_message["detection"] = detection
            zigbee_message["network_key_secret"] = dissector["link_key_secret"]
            report(f"zigbee message related to {dissector['nwk_addr_src']} formed", path)
            write_zigsniff_message(zigbee_message, path)
            # add key to zigbee_pc_keys
            key_management_add_key(dissector["link_key_secret"], path)

        elif "link_key_standard" in dissector:
            # Network key discovered message.
            detection = "Network Link Key has been found"
            zigbee_message["detection"] = detection
            zigbee_message["network_key_secret"] = dissector["link_key_standard"]
            report(f"zigbee message related to {dissector['nwk_addr_src']} formed", path)
            write_zigsniff_message(zigbee_message, path)
            # add key to zigbee_pc_keys
            key_management_add_key(dissector["link_key_standard"], path)

        elif "command_sensing_occupancy_occupied" in dissector:
            # Movement detected
            value = dissector["command_sensing_occupancy"]
            sticky_note = get_sticky_note(dissector["nwk_addr_src"], path)

            if sticky_note != "Error":
                if "command_sensing_occupancy_occupied" in sticky_note:
                    if sticky_note["command_sensing_occupancy_occupied"] != value:
                        sticky_note["command_sensing_occupancy_occupied"] = value
                    else:
                        return
                else:
                    sticky_note["command_sensing_occupancy_occupied"] = value

                if value == "0x00":
                    value = "no"
                elif value == "0x01":
                    value = "yes"
                else:
                    value = "Unknown"

                detection = f"Motion sensor detected occupancy"
                zigbee_message["detection"] = detection
                zigbee_message["action"] = value

                report(f"zigbee message related to { dissector['nwk_addr_src'] } formed", path)
                write_zigsniff_message(zigbee_message, path)

                if change_sticky_note(dissector["nwk_addr_src"], sticky_note, path) == 1:
                    report(sticky_note, path)
                    report(dissector, path)
                    report("Error occurred while creating Motion detection notification check at the sticky note update section", path)
                    exit()
            else:
                return

        elif "command_onoff_attr_onoff" in dissector:
            # Movement detected

            value = dissector["command_onoff_attr_onoff"]
            sticky_note = get_sticky_note(dissector["nwk_addr_src"], path)

            if sticky_note != "Error":
                if "src_endpoint" in dissector:
                    sticky_field = "command_onoff_attr_onoff_" + str(dissector['src_endpoint'])
                else:
                    sticky_field = "command_onoff_attr_onoff"

                if sticky_field in sticky_note:
                    if sticky_note[sticky_field] != value:
                        sticky_note[sticky_field] = value
                    else:
                        return
                else:
                    sticky_note[sticky_field] = value

                if value == "0x00":
                    value = "Off"
                elif value == "0x01":
                    value = "On"
                else:
                    value = "Unknown"

                detection = f"A switch request was triggered"
                zigbee_message["detection"] = detection
                zigbee_message["action"] = value

                report(f"zigbee message related to { dissector['nwk_addr_src'] } formed", path)
                write_zigsniff_message(zigbee_message, path)

                if change_sticky_note(dissector["nwk_addr_src"], sticky_note, path) == 1:
                    report(sticky_note, path)
                    report(dissector, path)
                    report("Error occurred while creating an ON OFF command check at the sticky note update section", path)
                    exit()
            else:
                return

        elif "command_onoff_cmd_id" in dissector:
            # Button press detected turns out its the lamps switching on
            detection = f"A Button was triggered"
            value = "unknown"
            if dissector['command_onoff_cmd_id'] == "0x01":
                value = "On"
            elif dissector['command_onoff_cmd_id'] == "0x00":
                value = "Off"
            elif dissector['command_onoff_cmd_id'] == "0x42":
                value = "On with timed Off"
            elif dissector['command_onoff_cmd_id'] == "0xfd":
                # Button cmd id is device specific and depends on the device
                value = "Device Specific 0xfd"
            else:
                value = "Unk Cmd " + str(dissector['command_onoff_cmd_id'])

            zigbee_message["detection"] = detection
            # Endp ID = Endpoint ID
            zigbee_message["action"] = f"Cmd ID: {value} Endp ID: {dissector['src_endpoint']}'"

            report(f"zigbee message related to {dissector['nwk_addr_src']} formed", path)
            write_zigsniff_message(zigbee_message, path)

        elif "command_zone_alarm_1" in dissector:
            # Movement detected
            value = dissector["command_zone_alarm_1"]
            sticky_note = get_sticky_note(dissector["nwk_addr_src"], path)

            if sticky_note != "Error":
                if "command_zone_alarm_1" in sticky_note:
                    if sticky_note["command_zone_alarm_1"] != value:
                        sticky_note["command_zone_alarm_1"] = value
                    else:
                        return
                else:
                    sticky_note["command_zone_alarm_1"] = value

                pkt_cluster = dissector["cluster"]
                if pkt_cluster == "0x0500":

                    if value == "0":
                        value = "Closed/Safe"
                    elif value == "1":
                        value = "Open/Alarm"
                    else:
                        value = "Unknown"

                    detection = f"Zone sensor status"
                    zigbee_message["detection"] = detection
                    zigbee_message["action"] = value

                else:
                    detection = f"Unknown cluster with command_zone_alarm_1"
                    zigbee_message["detection"] = detection
                    zigbee_message["action"] = dissector

                report(f"zigbee message related to { dissector['nwk_addr_src'] } formed", path)
                write_zigsniff_message(zigbee_message, path)

                if change_sticky_note(dissector["nwk_addr_src"], sticky_note, path) == 1:
                    report(sticky_note, path)
                    report(dissector, path)
                    report("Error occurred while creating an ON OFF command check at the sticky note update section", path)
                    exit()
            else:
                return

        else:
            pass
            report("Detection not handled", path)
            report(dissector, path)
            exit()

    except KeyError as e:
        report("-Detection error---------------------------------------------------", path)
        report(str(e), path)
        report(dissector, path)
        exit()