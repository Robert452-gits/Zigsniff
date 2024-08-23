#!/usr/bin/python3

import argparse
import pyshark
import os
import sys
import time
from apscheduler.schedulers.background import BackgroundScheduler
from pyshark.capture.pipe_capture import PipeCapture

from misc.zigsniff_utilities import report, create_work_directory, get_gps_loc
from zigbee_packet_dissector import zigbee_packet_dissector
import misc.zigsniff_config
from misc.zigsniff_sqlite import create_db, nwk_add_dev_to_devices, match_nwk_addresses, wpan_add_dev_to_devices, match_wpan_addresses, parse_the_rest, zigsniff_reporter
from misc.zigsniff_detections import zigbee_detections
from misc.zigsniff_whsniff import start_whsniff_process

# Script arguments
argParser = argparse.ArgumentParser(prog="Zigsniff", description="Passive capturing of Zigbee traffic and analysis of resulting data.", epilog="Powered by: Project Entropia")
argParser.add_argument("-p", "--pcap", type=str, help="Load Zigbee pcap file for processing.")
argParser.add_argument("-l", "--live", help="Perform live capture using CC2531.", action='store_true')
argParser.add_argument("-g", "--gps", help="Enable GPS by GPSD", action='store_true')
argParser.add_argument("-c", "--channel", type=int, default=11, help="Channel to capture on (11-26).")
argParser.add_argument("-C", "--config", type=str, default="zigsniff_config.json", help="Specify zigsniff config 'Default is zigsniff_config.json' (must be json!)")
argParser.add_argument("-o", "--output", type=str, default="messages", help="Write logs to path")
argParser.add_argument("-k", "--keyfile", type=str, default="zigbee_pc_keys", help="Pyshark/Wireshark Zigbee_pc_keys file for decryption using known keys")
args = argParser.parse_args()

if len(sys.argv) == 1:
    # Print help message and exit
    argParser.print_help()
    sys.exit()

# Lets set some variables
output = args.output
create_work_directory(output) # also print the start of the program.

# if live and config has been given as arguments
report("Starting Zigsniff with options:", output)  # to start things off
if args.live is not None:
    report(f"\tConfig file loaded", output)
    config = misc.zigsniff_config.config()
    args.channel = config.channel
    args.fifo_path = config.fifo_file_path
    args.report_period = config.report_period
    args.pcap_path = os.path.join(args.output, f"capture_{time.time()}.pcap")

else:
    channel = args.channel

# lets start processing and the works
for arg in vars(args): # report all arguments just for keepsake
    value = getattr(args, arg)
    if value is not None and value is not False:
        report(f"\t{arg}: {value}", output)

# maybe make a packet processor. we do some things duplicate given the arguments.

if args.live:
    report("Live capture starting:", output)
    # Start whsniff
    start_whsniff_process(args.channel, args.fifo_path, args.pcap_path, output)

    # in future start the webinterface at some point

    # schedule the report function
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(zigsniff_reporter, 'interval', seconds=config.report_period, args=[output, config.report_period])
    scheduler.start()

    # lets create the database
    create_db(output)  # Seeing that the folder now exists... lets create the sqlite file if needbe
    # Start monitoring fifo file
    with open(args.fifo_path, 'rb') as fifo:
        capture = PipeCapture(pipe=fifo)
        for packet in capture:
            dissector = zigbee_packet_dissector(packet)
            if dissector is not None and not isinstance(dissector, str):
                time_difference = int(time.time()) - dissector["pkt_timestamp"]
                if time_difference >= 60:
                    report(f"Timestamp from packet too old. stopping live capture. please restart: {time_difference}", output)
                    exit()
                else:
                    dissector['channel'] = int(args.channel)  # We have a packet and we add a channel to the output.

                    # add gps if enabled
                    if args.gps is True:
                        gps = get_gps_loc()
                        if gps is not None:
                            dissector['gps'] = gps

                    # First we need to make sure the device exists in the database. so we add it
                    if "nwk_mac_src" in dissector or "nwk_sec_src" in dissector:
                        if "nwk_mac_src" not in dissector:
                            dissector["nwk_mac_src"] = dissector["nwk_sec_src"]
                        nwk_add_dev_to_devices(dissector, output)
                        try:
                            # then we add all logical addresses to the database   ????
                            match_nwk_addresses(dissector["nwk_mac_src"], dissector["nwk_addr_src"], dissector["pan_dst"], dissector["nwk_addr_dst"], output)
                        except KeyError as e:
                            report(f"Added record to database error: {e}", output)

                    # if a device on logical level does not exist we can still add it from the wpan layer. but will have less details at start.
                    if "wpan_mac_src" in dissector:
                        wpan_add_dev_to_devices(dissector, output)

                    # adding all wpan destination addresses to a device entry so we see on wpan layer to what devices a device is communicating with.
                    if "wpan_addr_src" in dissector and "pan_dst" in dissector and "wpan_addr_dst" in dissector:
                        try:
                            match_wpan_addresses(dissector["wpan_addr_src"], dissector["pan_dst"], dissector["wpan_addr_dst"], output)
                        except KeyError as e:
                            report("Error in main wpan adding to database: " + str(e), output)

                    # Here we feed it to a module that adds small details to the database to make more sense of a device's capabilities
                    # May also help identify its purpose and functionality
                    if "nwk_addr_src" in dissector:
                        parse_the_rest(dissector, output)

                    # If a specific packet is discovered we want to generate a message (might).
                    # these packets are flagged with detection = 1. this indicates it has important information to create a .zmessage file.
                    if dissector["detection"] == 1:
                        dissector["pcap"] = str(args.pcap)  # add pcap name
                        zigbee_detections(dissector, output)

                    # process write files etc
                    elif isinstance(dissector, str):
                        # if it is an error please write it to file
                        report(f"-Error in Zigbee dissector---------------------------------------------", output)
                        report(f"{dissector}", output)
                        report(f"-End of error in Zigbee dissector--------------------------------------", output)

    # if timejump occures restart whsniff or restart/kill application

elif args.pcap is not None:
    report("Offline pcap processing starting:", output)

    # check if pcap exists and if it is a pcap?
    if not os.path.isfile(args.pcap):
        print(f"Pcap {args.pcap} file does not exist!")
        exit()
    # here check and build the database. if it does not exist yet.
    create_db(output)  # Seeing that the folder now exists... lets create the sqlite file if needed
    # open pcap with pyshark
    capture = pyshark.FileCapture(args.pcap)
    try:
        for packet in capture:
            # put packet into the zigbee dissector.
            dissector = zigbee_packet_dissector(packet)

            if dissector is not None and not isinstance(dissector, str):
                # Time jump problems do not exist in pcaps. no check needed
                # We add the channel. If you gave the correct channel we will use that
                dissector['channel'] = int(args.channel)  # We have a packet and we add a channel to the output.
                # maybe add gps here? update?
                #print(f"Packet: {dissector}")

                # First we need to make sure the device exists in the database. so we add it
                if "nwk_mac_src" in dissector or "nwk_sec_src" in dissector:
                    if "nwk_mac_src" not in dissector:
                        dissector["nwk_mac_src"] = dissector["nwk_sec_src"]
                    nwk_add_dev_to_devices(dissector, output)
                    try:
                        # then we add all logical addresses to the database   ????
                        match_nwk_addresses(dissector["nwk_mac_src"], dissector["nwk_addr_src"], dissector["pan_dst"], dissector["nwk_addr_dst"], output)
                    except KeyError as e:
                        report(f"Added record to database error: {e}", output)

                # if a device on logical level does not exist we can still add it from the wpan layer. but will have less details at start.
                if "wpan_mac_src" in dissector:
                    wpan_add_dev_to_devices(dissector, output)

                # adding all wpan destination addresses to a device entry so we see on wpan layer to what devices a device is communicating with.
                if "wpan_addr_src" in dissector and "pan_dst" in dissector and "wpan_addr_dst" in dissector:
                    try:
                        match_wpan_addresses(dissector["wpan_addr_src"], dissector["pan_dst"], dissector["wpan_addr_dst"], output)
                    except KeyError as e:
                        report("Error in main wpan adding to database: " + str(e), output)

                # Here we feed it to a module that adds small details to the database to make more sense of a device's capabilities
                # May also help identify its purpose and functionality
                if "nwk_addr_src" in dissector:
                    parse_the_rest(dissector, output)

                # If a specific packet is discovered we want to generate a message (might).
                # these packets are flagged with detection = 1. this indicates it has important information to create a .zmessage file.
                if dissector["detection"] == 1:
                    dissector["pcap"] = str(args.pcap) # add pcap name
                    zigbee_detections(dissector, output)

                # process write files etc
            elif isinstance(dissector, str):
                # if it is an error please write it to file
                report(f"-Error in Zigbee dissector----------------------------------------------------------------", output)
                report(f"{dissector}", output)
                report(f"-End of error in Zigbee dissector---------------------------------------------------------", output)

        # die
    except Exception as e:
        print(f"error occured:\n\n\n{e}")
        exit()
