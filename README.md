# Zigsniff
Written by: Robert

Zigsniff is zigbee sensing software built to generate single line json into files. 

It is built with the idea to run it inside a docker container.
It is purely used for passive observations!

## Zigbee Channels & required hardware
This program aims to monitor a single Zigbee channel.  
It is built to work with the flashed CC2531 from Texas Instruments.  
In the 2.4 Ghz range (Supported by CC2531) there are channels 11 to 26 (so 15).

## Basic functionality & workflow
Zigsniff starts the Whsniff application to use the CC2531 as an ingest interface and it gives an output of a PCAP stream.  
We write this to a PCAP and then follow it using PyShark (Tshark).  

The reason for PyShark is so we can load encryption keys with the same config file as we would in Wireshark.  
This makes life much easier!!  

Then we process each packet we receive en keep track of individual devices.  
We seperate them into 2 layers. We shall call the layers different here then in the specs so bear with me.  

We seperate into the Network layer. This shows what device a device is directly communicating with.  
So in Zigbee a Mesh network is built. Therefore Zigbee device A sends a message to device B intended for C.  
So for just 1 message we see 2 signals sent (when using the mesh network).  

The other layer we seperate into is the logical layer. So this would be the packets that say i am meant to go from A to C.  

Then when the state of a device is detected (many devices say they have the functionality of a switch. although technically true we as humans would not directly say, yes that is a switch.).  
Then when the state changes we write the updated change to the sqlite database overwriting the old state.  
This is done with all states so open or closed, temperature, battery percentage, switch state etc...  

## Output generated
So we ouptut an SQLite file containing all the details we collected from the pcap or live capture.  
Then when we see a special event that may indicate the interaction with a human we create a .zmessage file.  
Also every x seconds we dump an overview of the sqlite to device .zigsniff files.
