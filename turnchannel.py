#!/usr/bin/env python3

import sys
import pyshark

def analyze_turn_channels(pcap_file):
    # Load the capture file
    capture = pyshark.FileCapture(pcap_file, display_filter='(udp.port == 3478 || udp.port == 3479 || udp.port == 3480 || udp.port == 3481)')
    
    # Dictionary to store TURN channel numbers and their details
    turn_channels = {}
    
    for packet in capture:
        if 'STUN' in packet:
            if 'Allocate' in packet.stun:
                print(f"Found Allocate request in packet #{packet.number}")
            elif 'ChannelBind' in packet.stun:
                print(f"Found ChannelBind request in packet #{packet.number}")
                # Extract the channel number
                try:
                    channel_number = packet.stun.attribute_channelnumber
                    print(f"TURN Channel Number: {channel_number}")
                    turn_channels[channel_number] = packet.number
                except AttributeError:
                    print(f"No Channel Number found in packet #{packet.number}")

    capture.close()
    return turn_channels

# Path to your pcapng file

if __name__ == "__main__":

    pcap_file = sys.argv[1] if len(sys.argv) == 2 else None
    if (pcap_file is None):
        raise Exception("Please specify a pcap file.")

    # Analyze the pcap file and extract TURN channel numbers
    turn_channels = analyze_turn_channels(pcap_file)
    if (len(turn_channels) == 0):
        print("Got an empty list :(")

    # Print the results
    for channel, packet_num in turn_channels.items():
        print(f"Channel Number: {channel} found in Packet Number: {packet_num}")

