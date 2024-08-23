'''
    Returns dict with results if longer then 5.
    Returns nothing when results are shorter than 5 (means packet was not mentionable).
    Or returns str with error message when dissection is not correct.
    so check if it is a str None or a dict.

    When it is a str print the error to logfile and screen!
    When it is a Dict please continue as normal.... nothing to see here
    When it is None please move aside so the next packet can be processed.

    It takes a packet and checks if certain layers are inside it.
    When layer is inside, it just asks if values that have been determined to be interesting are present.
    In case they are the value is written in a dict and if all goes to plan returned at the end.

    Please check if the layer you are interested in is in this file. If not please debug and check
    If it is please add any fields you might want to have added. (may be harder because filters/fields not always match those in wireshark!)
    In case you want to see what is being skipped. print whatever is left over per layer.
'''
def zigbee_packet_dissector(pkt):
    gen_output = 0
    try:
        packet_layers = (str(pkt.layers))
        dissector_results = {}

        # Uncomment this for debugging (only prints to terminal not to log file)
        #print("################################################")
        #print(str(pkt.layers))
        #print("################################################")

        dissector_results["device_type"] = "unknown"
        dissector_results["detection"] = 0

        # check fcs
        if "_WS.MALFORMED Layer" in packet_layers:
            pkt_content_malformed = dir(pkt["_WS.MALFORMED"])
            for field in pkt_content_malformed:
                if field == "_ws_expert_severity":
                    return

        # packet general details
        if pkt.number != None:
            dissector_results["pkt_number"] = int(pkt.number)
        if pkt.sniff_timestamp != None:
            timestamp_epoch = str(pkt.sniff_timestamp).split(".", 1)[0]
            dissector_results["pkt_timestamp"] = int(timestamp_epoch)
        if pkt.length != None:
            dissector_results["pkt_length"] = int(pkt.length)
        if gen_output == 1:
            file_handle = open("output_packet_layers.log", "a")
            for field in packet_layers:
                file_handle.write(field)
            file_handle.write("\n")
            file_handle.close()

        if "WPAN" in packet_layers:
            pkt_content_wpan = dir(pkt["wpan"])
            for field in pkt_content_wpan:
                if field == "dst_pan":
                    dissector_results["pan_dst"] = str(pkt.wpan.dst_pan)
                elif field == "src_pan":
                    dissector_results["pan_src"] = str(pkt.wpan.src_pan)
                elif field == "src64":
                    dissector_results["wpan_mac_src"] = str(pkt.wpan.src64)
                elif field == "dst64":
                    dissector_results["wpan_mac_dst"] = str(pkt.wpan.dst64)
                elif field == "src16":
                    dissector_results["wpan_addr_src"] = str(pkt.wpan.src16)
                elif field == "dst16":
                    dissector_results["wpan_addr_dst"] = str(pkt.wpan.dst16)
                elif field == "cmd":
                    dissector_results["wpan_command"] = str(pkt.wpan.cmd)
                else:
                    if gen_output == 1:
                        file_handle = open("output_wpan_remaining_fields.log", "a")
                        file_handle.write(field + "\n")
                        file_handle.close()

        if "ZBEE_NWK" in packet_layers:
            pkt_content_zbee_nwk = dir(pkt["zbee_nwk"])
            for field in pkt_content_zbee_nwk:
                if field == "src64":
                    dissector_results["nwk_mac_src"] = str(pkt.zbee_nwk.src64)
                elif field == "dst64":
                    dissector_results["nwk_mac_dst"] = str(pkt.zbee_nwk.dst64)
                elif field == "dst":
                    dissector_results["nwk_addr_dst"] = str(pkt.zbee_nwk.dst)
                elif field == "src":
                    dissector_results["nwk_addr_src"] = str(pkt.zbee_nwk.src)
                elif field == "radius":
                    dissector_results["radius"] = str(pkt.zbee_nwk.radius)
                elif field == "end_device_initiator":
                    dissector_results["end_device_initiator"] = str(pkt.zbee_nwk.end_device_initiator)
                    if pkt.zbee_nwk.end_device_initiator == 0:
                        dissector_results["device_type"] = "Router"
                    elif pkt.zbee_nwk.end_device_initiator == 1:
                        dissector_results["device_type"] = "End Device"
                    else:
                        pass
                elif field == "zbee_sec_key_id":
                    dissector_results["key_id"] = str(pkt.zbee_nwk.zbee_sec_key_id)
                elif field == "zbee_sec_src64":
                    dissector_results["mac_sec_src"] = str(pkt.zbee_nwk.zbee_sec_src64)
                elif field == "addr64":
                    dissector_results["nwk_mac_src"] = str(pkt.zbee_nwk.addr64)
                elif field == "zbee_sec_key":
                    dissector_results["network_key"] = str(pkt.zbee_nwk.zbee_sec_key)
                elif field == "cmd_id":
                    dissector_results["cmd_id"] = str(pkt.zbee_nwk.cmd_id)
                    if str(pkt.zbee_nwk.cmd_id) == "0x02":
                        dissector_results["device_type"] = "Router"
                else:
                    if gen_output == 1:
                        file_handle = open("output_nwk_remaining_fields.log", "a")
                        file_handle.write(field + "\n")
                        file_handle.close()

        if "ZBEE_BEACON" in packet_layers:
            pkt_content_zbee_beacon = dir(pkt["zbee_beacon"])
            for field in pkt_content_zbee_beacon:
                if field == "router":
                    dissector_results["router_indicator"] = str(pkt.zbee_beacon.router)
                elif field == "depth":
                    dissector_results["device_depth"] = str(pkt.zbee_beacon.depth)
                elif field == "end_dev":
                    dissector_results["end_device_indicator"] = str(pkt.zbee_beacon.end_dev)
                elif field == "version":
                    dissector_results["protocol_version"] = str(pkt.zbee_beacon.version)
                else:
                    if gen_output == 1:
                        file_handle = open("output_beacon_remaining_fields.log", "a")
                        file_handle.write(field + "\n")

        if "ZBEE_APS" in packet_layers:
            pkt_content_zbee_aps = dir(pkt["zbee_aps"])
            for field in pkt_content_zbee_aps:
                if field == "profile":
                    dissector_results["packet_profile"] = str(pkt.zbee_aps.profile)
                elif field == "cluster":
                    dissector_results["cluster"] = str(pkt.zbee_aps.cluster)
                    if str(pkt.zbee_aps.cluster) == "0x8032":
                        dissector_results["device_type"] = "Router"
                    elif str(pkt.zbee_aps.cluster) == "0x0001":
                        dissector_results["device_type"] = "End Device"
                elif field == "zdp_cluster":
                    dissector_results["zdp_cluster"] = str(pkt.zbee_aps.zdp_cluster)
                    if str(pkt.zbee_aps.zdp_cluster) == "0x8032":
                        dissector_results["device_type"] = "Router"
                    # test if things get weird check here
                    elif str(pkt.zbee_aps.zdp_cluster) == "0x0001":
                        dissector_results["device_type"] = "End Device"
                elif field == "src":
                    dissector_results["src_endpoint"] = str(pkt.zbee_aps.src)
                elif field == "dst":
                    dissector_results["dst_enpoint"] = str(pkt.zbee_aps.dst)
                elif field == "cmd_key":
                    dissector_results["link_key_standard"] = str(pkt.zbee_aps.cmd_key)
                    dissector_results["detection"] = 1
                elif field == "zbee_sec_key":
                    dissector_results["link_key_secret"] = str(pkt.zbee_aps.zbee_sec_key)
                    dissector_results["detection"] = 1
                else:
                    if gen_output == 1:
                        file_handle = open("output_aps_remaining_fields.log", "a")
                        file_handle.write(field + "\n")
                        file_handle.close()

        if "ZBEE_ZCL" in packet_layers:
            pkt_content_zbee_zcl = dir(pkt["zbee_zcl"])
            for field in pkt_content_zbee_zcl:
                if field == "zbee_zcl_lighting_color_control_attr_color_temperature":
                    dissector_results["command_color_temperature"] = str(pkt.zbee_zcl.zbee_zcl_lighting_color_control_attr_color_temperature)
                    dissector_results["device_type"] = "Router"
                elif field == "zbee_zcl_lighting_color_control_attr_color_x":
                    dissector_results["command_color_attr_color_x"] = str(pkt.zbee_zcl.zbee_zcl_lighting_color_control_attr_color_x)
                    dissector_results["device_type"] = "Router"
                elif field == "zbee_zcl_lighting_color_control_attr_color_y":
                    dissector_results["command_color_attr_color_y"] = str(pkt.zbee_zcl.zbee_zcl_lighting_color_control_attr_color_y)
                    dissector_results["device_type"] = "Router"
                elif field == "zbee_zcl_lighting_color_control_attr_id":
                    dissector_results["command_color_control_id"] = str(pkt.zbee_zcl.zbee_zcl_lighting_color_control_attr_id)
                elif field == "zbee_zcl_meas_sensing_elecmes_attr_id":
                    dissector_results["command_power_attr_id"] = str(pkt.zbee_zcl.zbee_zcl_meas_sensing_elecmes_attr_id)
                elif field == "zbee_zcl_general_power_config_attr_id":
                    dissector_results["command_power_config_attr_id"] = str(pkt.zbee_zcl.zbee_zcl_general_power_config_attr_id)
                elif field == "zbee_zcl_meas_sensing_illummeas_attr_value":
                    dissector_results["command_illummeas_value"] = float(pkt.zbee_zcl.zbee_zcl_meas_sensing_illummeas_attr_value) / 100.0
                elif field == "zbee_zcl_meas_sensing_occsen_attr_occupancy":
                    dissector_results["command_sensing_occupancy"] = str(pkt.zbee_zcl.zbee_zcl_meas_sensing_occsen_attr_occupancy)
                elif field == "zbee_zcl_meas_sensing_occsen_attr_occupancy_occupied":
                    dissector_results["command_sensing_occupancy_occupied"] = pkt.zbee_zcl.zbee_zcl_meas_sensing_occsen_attr_occupancy_occupied
                    dissector_results["detection"] = 1
                elif field == "zbee_zcl_general_level_control_attr_id":
                    dissector_results["command_level_control_attr_id"] = str(pkt.zbee_zcl.zbee_zcl_general_level_control_attr_id)
                elif field == "zbee_zcl_general_level_control_attr_current_level":
                    dissector_results["command_level_control_current_level"] = str(pkt.zbee_zcl.zbee_zcl_general_level_control_attr_current_level)
                elif field == "zbee_zcl_general_onoff_attr_id":
                    dissector_results["command_onoff_attr_id"] = str(pkt.zbee_zcl.zbee_zcl_general_onoff_attr_id)
                elif field == "zbee_zcl_general_onoff_attr_onoff":
                    dissector_results["command_onoff_attr_onoff"] = str(pkt.zbee_zcl.zbee_zcl_general_onoff_attr_onoff)
                    dissector_results["detection"] = 1
                elif field == "zbee_zcl_ias_zone_status_battery":
                    dissector_results["command_battery_status"] = str(pkt.zbee_zcl.zbee_zcl_ias_zone_status_battery)
                    dissector_results["device_type"] = "End Device"
                elif field == "zbee_zcl_ias_zone_status":
                    dissector_results["command_level_zone_status"] = str(pkt.zbee_zcl.zbee_zcl_ias_zone_status)
                elif field == "zbee_zcl_ias_zone_status_ac_mains":
                    dissector_results["command_ac_mains"] = str(pkt.zbee_zcl.zbee_zcl_ias_zone_status_ac_mains)
                elif field == "zbee_zcl_ias_zone_status_alarm_1":
                    dissector_results["command_zone_alarm_1"] = str(pkt.zbee_zcl.zbee_zcl_ias_zone_status_alarm_1)
                    dissector_results["detection"] = 1
                elif field == "zbee_zcl_ias_zone_status_alarm_2":
                    dissector_results["command_zone_alarm_2"] = str(pkt.zbee_zcl.zbee_zcl_ias_zone_status_alarm_2)
                elif field == "zbee_zcl_meas_sensing_pressmeas_attr_scaled_value":
                    dissector_results["command_pressure_level_detail"] = float(pkt.zbee_zcl.zbee_zcl_meas_sensing_pressmeas_attr_scaled_value) / 100.0
                elif field == "zbee_zcl_meas_sensing_tempmeas_attr_value":
                    dissector_results["command_temperature_measured"] = float(pkt.zbee_zcl.zbee_zcl_meas_sensing_tempmeas_attr_value) / 100.0
                elif field == "zbee_zcl_meas_sensing_relhummeas_attr_value":
                    dissector_results["command_humidity_measured"] = float(pkt.zbee_zcl.zbee_zcl_meas_sensing_relhummeas_attr_value) / 100.0
                elif field == "zbee_zcl_general_power_config_attr_batt_percentage":
                    dissector_results["command_battery_percentage"] = float(pkt.zbee_zcl.zbee_zcl_general_power_config_attr_batt_percentage) / 2
                    dissector_results["device_type"] = "End Device"
                elif field == "zbee_zcl_general_power_config_attr_batt_voltage":
                    dissector_results["command_battery_voltage"] = float(pkt.zbee_zcl.zbee_zcl_general_power_config_attr_batt_voltage) / 10
                    dissector_results["device_type"] = "End Device"
                elif field == "zbee_zcl_general_onoff_cmd_srv_rx_id":
                    dissector_results["command_onoff_cmd_id"] = str(pkt.zbee_zcl.zbee_zcl_general_onoff_cmd_srv_rx_id)
                    dissector_results["detection"] = 1
                elif field == "zbee_zcl_general_ota_manufacturer_code":
                    dissector_results["ota_manufacturer_code"] = str(pkt.zbee_zcl.zbee_zcl_general_ota_manufacturer_code)
                elif field == "zbee_zcl_general_ota_hw_ver":
                    dissector_results["ota_hardware_version"] = str(pkt.zbee_zcl.zbee_zcl_general_ota_hw_ver)
                elif field == "zbee_zcl_general_ota_image_type":
                    dissector_results["ota_image_type"] = str(pkt.zbee_zcl.zbee_zcl_general_ota_image_type)
                elif field == "zbee_zcl_general_ota_status":
                    dissector_results["ota_status"] = str(pkt.zbee_zcl.zbee_zcl_general_ota_status)
                elif field == "zbee_zcl_general_ota_file_version":
                    dissector_results["ota_file_version"] = str(pkt.zbee_zcl.zbee_zcl_general_ota_file_version)
                elif field == "type":
                    dissector_results["zcl_type"] = str(pkt.zbee_zcl.type)

                # Philips hue specific!!!
                elif field == "zbee_zcl_lighting_color_control_attr_current_hue":
                    dissector_results["zbee_zcl_lighting_color_control_attr_current_hue"] = str(pkt.zbee_zcl.zbee_zcl_lighting_color_control_attr_current_hue)
                else:
                    if gen_output == 1:
                        file_handle = open("output_zcl_remaining_fields.log", "a")
                        file_handle.write(field + "\n")
                        file_handle.close()

        if "DATA" in packet_layers:
            pkt_content_data = dir(pkt.DATA)
            for field in pkt_content_data:
                if field == "data_len":
                    dissector_results["data_packet_length"] = str(pkt.DATA.data_len)
                else:
                    if gen_output == 1:
                        file_handle = open("output_data_remaining_fields.log", "a")
                        file_handle.write(field + "\n")
                        file_handle.close()

        if "ZBEE_ZDP" in packet_layers:
            pkt_content_zbee_zdp = dir(pkt["zbee_zdp"])
            for field in pkt_content_zbee_zdp:
                if field == "cinfo":
                    dissector_results["zdp_cinfo_record_type"] = str(pkt.zbee_zdp.cinfo)
                elif field == "cinfo_alt_coord":
                    dissector_results["zdp_cinfo_alternate_coordinator"] = str(pkt.zbee_zdp.cinfo_alt_coord)
                elif field == "cinfo_ffd":
                    dissector_results["zdp_cinfo_full_function_device"] = str(pkt.zbee_zdp.cinfo_ffd)
                    dissector_results["device_type"] = "Router"
                elif field == "cinfo_power":
                    dissector_results["zdp_cinfo_ac_power"] = str(pkt.zbee_zdp.cinfo_power)
                    dissector_results["device_type"] = "Router"
                elif field == "cinfo_idle_rx":
                    dissector_results["zdp_cinfo_when_idle_rx_on"] = str(pkt.zbee_zdp.cinfo_idle_rx)
                elif field == "cinfo_security":
                    dissector_results["zdp_cinfo_security"] = str(pkt.zbee_zdp.cinfo_security)
                elif field == "cinfo_alloc":
                    dissector_results["zdp_cinfo_allocate_short_addr"] = str(pkt.zbee_zdp.cinfo_alloc)
                elif field == "node_complex":
                    dissector_results["zdp_node_complex"] = str(pkt.zbee_zdp.node_complex)
                elif field == "node_freq_2400mhz":
                    dissector_results["zdp_node_freq_2400"] = str(pkt.zbee_zdp.node_freq_2400mhz)
                elif field == "node_freq_868mhz":
                    dissector_results["zdp_node_freq_868"] = str(pkt.zbee_zdp.node_freq_868mhz)
                elif field == "node_freq_900mhz":
                    dissector_results["zdp_node_freq_900"] = str(pkt.zbee_zdp.node_freq_900mhz)
                elif field == "node_freq_eu_sub_ghz":
                    dissector_results["zdp_node_freq_eu_fsk"] = str(pkt.zbee_zdp.node_freq_eu_sub_ghz)
                elif field == "node_manufacturer":
                    dissector_results["zdp_node_manufacturer"] = str(pkt.zbee_zdp.node_manufacturer)
                elif field == "node_max_buffer":
                    dissector_results["zdp_node_max_buffer"] = str(pkt.zbee_zdp.node_max_buffer)
                elif field == "node_max_incoming_transfer":
                    dissector_results["zdp_node_max_incomming_trans"] = str(pkt.zbee_zdp.node_max_incoming_transfer)
                elif field == "node_max_outgoing_transfer":
                    dissector_results["zdp_node_max_outgoing_trans"] = str(pkt.zbee_zdp.node_max_outgoing_transfer)
                elif field == "duration":
                    dissector_results["zdp_node_duration"] = pkt.zbee_zdp.duration
                elif field == "lqi":
                    dissector_results["zdp_node_lqi"] = pkt.zbee_zdp.lqi
                elif field == "status":
                    dissector_results["zdp_node_status"] = int(pkt.zbee_zdp.status)
                elif field == "node_type":
                    value = pkt.zbee_zdp.node_type
                    if value == 0:
                        dissector_results["device_type"] = "Coordinator"
                    dissector_results["zdp_node_type"] = value
                elif field == "node_user":
                    dissector_results["zdp_node_user"] = str(pkt.zbee_zdp.node_user)

                # this field needs more work. lots of data remains!! warning
                elif field == "table_count":
                    if field == "table_entry_type":
                        dissector_results["zdp_lqr_contents"] = str(pkt.zbee_zdp.table_entry_type)
                    elif field == "table_count":
                        dissector_results["zdp_lqr_table_count"] = str(pkt.zbee_zdp.table_count)
                    elif field == "table_count": # when fixed delete this elif
                        dissector_results["zdp_lqr_warning"] = "Warning - Needs work. check pcaps"

                else:
                    if gen_output == 1:
                        file_handle = open("output_zdp_remaining_fields.log", "a")
                        file_handle.write(field + "\n")
                        file_handle.close()

        if len(dissector_results) > 5:
            return dissector_results

    except KeyError as e:
        return str(e)
