import argparse
from scapy.all import *
import sys
import random
import threading

def send_beacon(netSSID, mac, infinite=True):
    ''' 왜 안될까요..ㅠㅠ
    radiotap = RadioTap(present=0xa00048ee, Flags=0x10, Rate=1, ChannelFrequency=2412,ChannelFlags=0x00a0, dBm_AntSignal=-95, dBm_AntNoise=-1, Lock_Quality=100)
    '''
    dot11 = Dot11(type=0, subtype=8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = mac, addr3 = mac)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=netSSID, len=len(netSSID))
    
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'
    '\x00\x0f\xac\x02'
    '\x02\x00'
    '\x00\x0f\xac\x04'
    '\x00\x0f\xac\x02'
    '\x01\x00'
    '\x00\x0f\xac\x02'
    '\x00\x00'))
    
    frame = RadioTap()/dot11/beacon/essid/rsn/Dot11EltRates()
    
    '''
    frame.show()
    print("\nHexDump of frame:")
    hexdump(frame)
    
    input("\nPress enter to start\n")
    '''
    
    sendp(frame, iface=iface, inter=0.100, loop=1)

if __name__ == '__main__':

    ssid_list = []
    argument = sys.argv
    del argument[0]
    print(f'Argument : {argument}')

    if len(argument) != 2:
        print("syntax : python bf.py <interface> <ssid-list-file>\nsample : python bf.py mon0 ssid-list.txt")
        quit()
    
    filename = argument[1]
    f = open(filename, 'r')
    
    lines = f.read()
    ssid_list = lines.split('\n')
    
    print(ssid_list)

    iface = argument[0]
    
    ssids_macs = [(ssid_list[i], str(RandMAC())) for i in range(0,len(ssid_list))]
    print(ssids_macs)
    for ssid, mac in ssids_macs:
        threading.Thread(target=send_beacon, args=(ssid, mac)).start()