#!/usr/bin/env python2
# Author: Pieter Robyns, 2017
# License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
# See LICENSE in this Git repository for the full license description
#
# This script contains the code for performing the transmission rate experiments.
# The first 157 lines of code can be safely ignored: these lines essentially
# create some tryout frames for a handful of personal devices. I have anonymized
# the last three bytes of the MAC addresses. The code after this will first scan
# for neighbouring MAC addresses and subsequently inject each of the frame types
# in a zero, broadcast, BSSID, and unicast scenario. The results will be written
# to both a pcap and a csv.

from scapy.layers.dot11 import RadioTap, Dot11, Raw, sendp, hexdump, sniff, EAP, wrpcap
from scapy.layers.inet import Ether, SNAP, LLC
from rpyutils import get_frequency, get_if_raw_hwaddr
import struct
import crcmod
import threading
import os
from collections import defaultdict
from time import time, sleep
from netaddr import *
from pprint import pprint

# 802.11 MAC CRC
def dot11crc(pkt):
    crc_fun = crcmod.Crc(0b100000100110000010001110110110111, rev=True, initCrc=0x0, xorOut=0xFFFFFFFF)
    crc_fun.update(str(pkt))
    crc = struct.pack('<I', crc_fun.crcValue)
    return crc

interface = 'mon0'

own_mac = get_if_raw_hwaddr(interface)[1]
src_mac = own_mac
dst_mac = 'ff:ff:ff:ff:ff:ff'
#dst_mac = 'c0:ee:fb:00:00:00' # OnePlus?
#dst_mac = '00:1c:10:00:00:00' # Linksys router
src_mac = '00:1c:10:00:00:00' # Linksys router
channel = 1
sequence_number = 0

rt = RadioTap(len=18, present='Flags+Rate+Channel+dBm_AntSignal+Antenna', notdecoded='\x00\x6c' + get_frequency(channel) + '\xc0\x00\xc0\x01\x00\x00')

def next_sc():
    global sequence_number
    sequence_number = (sequence_number + 1) % 4096

    return sequence_number*16

# Template, xx = length
#pkt = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=src_mac, SC=0, FCfield='from-DS') \
#      / "\x00\x00\x01\x26\xx\x00\x0e\x00"

# Radio measurement
# --------------------------------------------------
#pkt = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=src_mac, SC=0, FCfield=0) \
#      / "\x00\x00\x01\x26\x0e\x00\x0e\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"

# Channel Load Request (3): "\x04\x01\x00\x00\xff\xff"
# ------------------------------------------------------------------------------------------------
# STA statistics request (7): 6 bytes peer, 2 rand, 2 dura, 1 ident:
#pkt = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=src_mac, SC=0, FCfield=0) \
#      / "\x00\x00\x01\x26\x0e\x00\x0e\x07\xc8\xf6\x50\xf3\x47\x7d\x00\x00\xff\xff\x00"

# Enable
#pkt_en = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=src_mac, SC=0, FCfield=0) \
#         / "\x00\x00\x01\x26\03\x00\x0e\x00"

#intel_checksum = dot11crc(pkt)
#pkt = pkt / intel_checksum

#intel_checksum_en = dot11crc(pkt_en)
#pkt_en = pkt_en / intel_checksum_en

# Link measurement -- response but error
# -------------------------------------------------

# Request
# 1 byte Category
# 1 byte Radio Measurement Action
# 1 byte Dialog token
# 1 byte Transmit power used
# 1 byte Max transmit power
# x byte Optional
#   1 byte
#pkt = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=src_mac, SC=0, FCfield=0) \
#      / "\x05\x02\x01\x10\x10"


# TDLS -- get response but error
# --------------------------------------------------
# Category 12
# Request 10
# Dialog 1
# 1 byte element ID
# 1 byte length
# 6 bytes BSSID
# 6 bytes sender
# 6 bytes responder
# Linksys : \x00\x1c\x10\x00\x00\x00
# My MAC  : \x10\xfe\xed\x00\x00\x00
# iPad MAC: \xc8\xf6\x50\x00\x00\x00
# Nexus   : \x64\x89\x9a\x00\x00\x00
# BR      : \xff\xff\xff\xff\xff\xff
# Bram    : \xc0\x4a\x00\x00\x00\x00
# hostapd : \x10\x0d\x7f\x00\x00\x00 (Netgear)
tplink = '\x10\xfe\xed\x00\x00\x00'
mynexus = '\x64\x89\x9a\x00\x00\x00' # 64:89:9a:00:00:00
br = '\xff\xff\xff\xff\xff\xff'
zero = '\x00\x00\x00\x00\x00\x00'
netg = '\x10\x0d\x7f\x00\x00\x00'
ipad = '\xc8\xf6\x50\x00\x00\x00'
ubi = "\x24\xa4\x3c\x00\x00\x00"
src_mac = own_mac
dst_mac = '\xc8\xf6\x50\x00\x00\x00'
#pkt = Dot11(type=2, subtype=0, addr1=dst_mac, addr2=src_mac, addr3=netg, SC=0, FCfield=0) \
#      / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
#      / SNAP(OUI=0x000000, code=0x890d) \
#      / "\x02\x0c\x0a\x01\x65\x12\x10\x0d\x7f\x26\x4f\x17\x10\xfe\xed\x1d\xae\xca\xc8\xf6\x50\xf3\x47\x7d"

# GAS
# 1 byte Elem ID: \x6c
# 1 byte Length of info and adv protocol id
# 1 byte QueryResponse Info: kies \xff (p780) OF NEE WACHT 0x80
# 1 byte Advertisement Protocol ID: \x00 (p781)
# 2 bytes Query Request length
    # 2 byte info ID == 256 == \x00\x01?
    # 2 bytes length (num of ids * 2)
    # info ID of requested info \x01\x01
netg = '\x10\x0d\x7f\x00\x00\x00'
tplinkmini = '\xc0\x4a\x00\x00\x00\x00' # c0:4a:00:00:00:00
nexus6 = '\xec\x88\x92\x00\x00\x00'
src_mac = tplink
dst_mac = br

# Query list
#pkt2 = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=zero, SC=0, FCfield=0) \
#      / "\x04\x0a\x01\x6c\x02\xff\x00\x06\x00\x00\x01\x02\x00\x01\x01"

# P2P GAS Request, working for IP cam (Axis Communications)
# Broadcast works for Axis,
# Directed works for wpa_supp (dst_mac zowel addr1 als addr3 en src mac klopt)
# BROADCAST works for wpa_supp if addr3==000000000000
# BROADCAST works for samsung when addr3 == fffffffff, but not for wpa_supplicant. Only Samsung responds to addr3==fffffffff
#pkt3 = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=br, SC=0, FCfield=0) \
#      / "\x04\x0a\x01\x6c\x02\xff\x00\x0a\x00\xdd\xdd\x06\x00\x50\x6f\x9a\x09\x01\x00"

gas_resp = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=netg, SC=0, FCfield=0) \
    / "\x04\x0b\xee\x00\x00\x00\x00\x6c\x02\x7f\x00\x22\x00\x01\x01\x11\x00\x01\x01\x02\x01\xdd\xdd\x09\x00\x50\x6f\x9a\x11\x02\x00\x02\x03\x04\xdd\xdd\x09\x00\x50\x6f\x9a\x11\x02\x00\x02\x03\x04"


wpa_supp_gas_query = Dot11(type=0, subtype=13, addr1=dst_mac, addr2=src_mac, addr3=dst_mac, SC=0, FCfield=0) \
    / "\x04\x0a\x02\x6c\x02\x00\x00\x19\x00\x00\x01\x0a\x00\x01\x01\x05\x01\x07\x01\x08\x01\x0c\x01\xdd\xdd\x07\x00\x50\x6f\x9a\x11\x01\x00\x02"

null_dat = Dot11(type=2, subtype=4, addr1=mynexus, addr2=mynexus, addr3=mynexus, SC=0, FCfield=0)  # Appears to work for TP link

# A TDLS STA may also send a TDLS Setup Request frame to a STA in the same BSS to discover whether the TDLS peer STA is TDLS capable or not. A TDLS Setup Response frame transmitted in response to TDLS Setup Request frame indicates that the TDLS peer STA sending the TDLS Setup Response is TDLS capable.
def send_tdls_disc(bssid, src, dst):
    global token
    discovery_request = Dot11(type=2, subtype=0, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
    / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
    / SNAP(OUI=0x000000, code=0x890d) \
    / ("\x02\x0c\x0a\x01\x65\x12" + bssid + src + dst)

    sendp(rt / discovery_request, iface=interface, verbose=False, loop=0)

def send_tdls_setup(bssid, src, dst):
    global token
    setup_request = Dot11(type=2, subtype=0, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
    / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03) \
    / SNAP(OUI=0x000000, code=0x890d) \
    / ("\x02\x0c\x00\x01\xff\xff")
    # Dialog token - capabilities - supported rates

    sendp(rt / setup_request, iface=interface, verbose=False, loop=0)

def send_wnm_eventreq(bssid, src, dst):
    global token
    #subel = "\x01\x02\x04\x01"  # Channel Number subelement
    subel = ""  # Empty subel
    values = token + "\x02\x00" + subel
    length = struct.pack("B", len(values))
    elem = "\x4E" + length + values
    tim_wireshark = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
    / ("\x0a\x00" + elem)

    tim_standard = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
/ ("\x0a\x00" + token + elem)

    sendp(rt / tim_wireshark, iface=interface, verbose=False, loop=0)
    sendp(rt / tim_standard, iface=interface, verbose=False, loop=0)

def send_wnm_meas(bssid, src, dst):
    global token
    meas_wireshark = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
    / ("\x0a\x19")
    meas_standard = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
    / ("\x0a\x19\x01")

    sendp(rt / meas_wireshark, iface=interface, verbose=False, loop=0)
    sendp(rt / meas_standard, iface=interface, verbose=False, loop=0)

def back_req(bssid, src, dst):
    global token
    sendp(rt / ("\xd0\x00\x3a\x01" + dst + src + bssid + "\xb0\xb0\x03\x00\x69\x02\x10\x00\x00\x60\xcd"), iface=interface, verbose=False, loop=0)

def send_dot11u(bssid, src, dst):
    global token
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
              / ("\x04\x0a" + token + "\x6c\x02\xff\x00\x0a\x00\xdd\xdd\x06\x00\x50\x6f\x9a\x09" + token + "\x00")
    sendp(rt / initial, iface=interface, verbose=False, loop=0)

def send_dot11u_ql(bssid, src, dst):
    global token
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
          / ("\x04\x0a" + token + "\x6c\x02\xff\x00\x06\x00\x00\x01\x02\x00\x01\x01")
    sendp(rt / initial, iface=interface, verbose=False, loop=0)

# Measurement Types 0, 1, and 2 are defined for spectrum management and are included only in Spectrum Management Measurement Request frames. The use of Measurement Request elements for spectrum management is described in 10.9.7. Measurement Types 3 to 9 and 255 are defined for radio measurement and are included only in Radio Measurement Request frames.

# Works for A LOT of devices if BSSID can be guessed
def send_basic_req(bssid, src, dst):
    global token
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
      / ("\x00\x00" + token + "\x26\x0e\x01\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00")
    sendp(rt / initial, iface=interface, verbose=False, loop=0)

def send_cca(bssid, src, dst):
    global token
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
      / ("\x00\x00" + token + "\x26\x0e\x01\x0e\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00")
    sendp(rt / initial, iface=interface, verbose=False, loop=0)

# Works for OnePlus; response is "Basic Report"
def send_load_req(bssid, src, dst):
    global token
    #initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
    #  / ("\x05\x00" + token + "\x00\x01" +
    #  "\x26\x09\x01\x0e\x03\x04\x00\xff\xff\x00\x00")
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
      / ("\x05\x00" + token + "\x00\x01" +
      "\x26\x0d\x01\x0e\x03\x04\x00\x00\x00\x64\x00\x01\x02\x01\x00")
    sendp(rt / initial, iface=interface, verbose=False, loop=0)

# Works for OnePlus
def send_statistics_req(bssid, src, dst):
    global token
    subel = "\x01\x10\x01\x00\x00\x00\xff\xff\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    length = struct.pack("B", len(subel) + 3 + 6 + 5)
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
      / ("\x05\x00"+token+"\x00\x01"+"\x26"+length+"\x01\x0e\x07" + dst + "\xff\xff\x00\x00\x00" + subel)
    sendp(rt / initial, iface=interface, verbose=False, loop=0)

# Works for OnePlus
def send_frame_req(bssid, src, dst):
    global token
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
      / ("\x05\x00"+token+"\x00\x01"+"\x26\x10\x00\x0e\x06\x04\x00\xff\xff\x00\xff\x01\xff\xff\xff\xff\xff\xff")
    sendp(rt / initial, iface=interface, verbose=False, loop=0)


# Works for OnePlus
def send_link_measurement(bssid, src, dst):
    global token
    initial = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=bssid, SC=next_sc(), FCfield=0) \
      / ("\x05\x02"+token+"\x10\x10")
    sendp(rt / initial, iface=interface, verbose=False, loop=0)

state_names = {
    0:  'GAS Request (broadcast BSSID)',
    1:  'GAS Request (zeros BSSID)',
    2:  'GAS Request (bssids)',
    3:  'GAS Request (unicast)',
    4:  'ADDBA Request (broadcast BSSID)',
    5:  'ADDBA Request (zeros BSSID)',
    6:  'ADDBA Request (bssids)',
    7:  'ADDBA Request (unicast)',
    8:  'WNM Event Request (broadcast BSSID)',
    9:  'WNM Event Request (zeros BSSID)',
    10: 'WNM Event Request (bssids)',
    11: 'WNM Event Request (unicast)',
    12: 'WNM Timing Measurement Request (broadcast BSSID)',
    13: 'WNM Timing Measurement Request (zeros BSSID)',
    14: 'WNM Timing Measurement Request (bssids)',
    15: 'WNM Timing Measurement Request (unicast)',
    16: 'TDLS Discovery (broadcast BSSID)',
    17: 'TDLS Discovery (zeros BSSID)',
    18: 'TDLS Discovery (bssids)',
    19: 'TDLS Discovery (unicast)',
    20: 'TDLS Setup (broadcast BSSID)',
    21: 'TDLS Setup (zeros BSSID)',
    22: 'TDLS Setup (bssids)',
    23: 'TDLS Setup (unicast)',
    24: 'Basic Spectrum (broadcast BSSID)',
    25: 'Basic Spectrum (zeros BSSID)',
    26: 'Basic Spectrum (bssids)',
    27: 'Basic Spectrum (unicast)',
    28: 'Load Request (broadcast BSSID)',
    29: 'Load Request (zeros BSSID)',
    30: 'Load Request (bssids)',
    31: 'Load Request (unicast)',
    32: 'STA Statistics Request (broadcast BSSID)',
    33: 'STA Statistics Request (zeros BSSID)',
    34: 'STA Statistics Request (bssids)',
    35: 'STA Statistics Request (unicast)',
    36: 'Clear Channel Assessment (broadcast BSSID)',
    37: 'Clear Channel Assessment (zeros BSSID)',
    38: 'Clear Channel Assessment (bssids)',
    39: 'Clear Channel Assessment (unicast)',
    40: 'Frame Request (broadcast BSSID)',
    41: 'Frame Request (zeros BSSID)',
    42: 'Frame Request (bssids)',
    43: 'Frame Request (unicast)',
    44: 'Link Measurement (broadcast BSSID)',
    45: 'Link Measurement (zeros BSSID)',
    46: 'Link Measurement (bssids)',
    47: 'Link Measurement (unicast)',
}

state_actions = {
    0: send_dot11u,
    1: back_req, # Intel
    2: send_wnm_eventreq,
    3: send_wnm_meas,
    4: send_tdls_disc,
    5: send_tdls_setup,
    6: send_basic_req,
    7: send_load_req,
    8: send_statistics_req,
    9: send_cca,
    10: send_frame_req,
    11: send_link_measurement,
    12: None
}

class TestCase:
    BROADCAST = 0
    ZERO = 1
    BSSIDS = 2
    UNICAST = 3
    MAX = 4

eapol_ids = defaultdict(lambda: None)
class Sample():
    def __init__(self, caught_in_state, pkt):
        self.state = caught_in_state
        self.mac = pkt[Dot11].addr2
        self.pkt = pkt

    def __str__(self):
        global eapol_ids
        global state_names

        state = str(state_names[self.state])
        mac = self.mac
        try:
            oui = EUI(mac).oui.registration().org.replace(',','')
        except Exception:
            oui = "Unknown"
            pass
        owner = str(eapol_ids[mac])

        return "{0:s},{1:s},{2:s},{3:s}".format(state, mac, oui, owner)

    def __hash__(self):
        return hash(self.mac)

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not (hash(self) == hash(other))

current_state = 0
current_testcase = TestCase.BROADCAST
macs_seen_state = defaultdict(lambda: set())
spoof_mac = "10:fe:ed:00:00:00"

class Sniffer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.sniffer_mac = spoof_mac

    def analyze(self, pkt):
        global current_state
        global current_testcase
        global macs_seen_state
        global bssids
        global stas

        # Skip non-Dot11 stuff
        if not Dot11 in pkt:
            return

        # Skip unknown OUIs
        try:
            oui = EUI(pkt.addr2).oui.registration().org
        except Exception:
            return

        # Not AP? Then its a peer STA
        if not pkt.addr2 in bssids:
            stas.add(pkt.addr2)

        # Dont do anything if not data or action
        if (not (pkt[Dot11].subtype == 13 and pkt[Dot11].type == 0)) and (not pkt[Dot11].type == 2):
            return

        # If we're not doing the block ack experiment, not interested in block acks
        if not current_state == 1 and Raw in pkt and str(pkt[Raw])[0] == "\x03":
            return

        # Check only responses if spoofing BSSIDs
        if current_testcase == TestCase.BSSIDS and not pkt[Dot11].addr1 in bssids:
            return

        # Check both stimulus frame and response if otherwise
        if current_testcase != TestCase.BSSIDS and (pkt[Dot11].addr1 != self.sniffer_mac and pkt[Dot11].addr2 != self.sniffer_mac):
            return

        index = (current_state * TestCase.MAX) + current_testcase
        macs_seen_state[index].add(Sample(index, pkt))
        print(chr(27) + "[2J")
        print("Experiment {0}, test case {1} ({2})".format(current_state, current_testcase, index))
        print("Samples (" + state_names[index] + "):")
        for sample in macs_seen_state[index]:
            print(sample)
        print("")
        #print("IDs:")
        #for identities in eapol_ids:
        #    print(identities + " -> " + str(eapol_ids[identities]))

        if EAP in pkt:
            if pkt[EAP].code == 2 and pkt[EAP].type == 1:
                eapol_ids[pkt[Dot11].addr2] = str(pkt[Raw])[:-4]

    def run(self):
        print("Starting experiment")
        sniff(iface=interface, prn=self.analyze, store=0, filter="wlan type mgt or (wlan type data subtype data and len <= 110)")

def send_multi_bssid(method, bssid_list, src, dst):
    for bssid in bssid_list:
        bssid = bssid.replace(':', '').decode('hex')
        method(bssid, bssid, dst)  # Note: here it's bssid, bssid instead of bssid, src!

def send_multi_unicast(method, bssid, src, dst_list):
    loop = dst_list.copy()  # Unicast list is constantly updated, so copy it
    for dst in loop:
        dst = dst.replace(':', '').decode('hex')
        method(bssid, src, dst)

class MACScanner(threading.Thread):
    def __init__(self, num_seconds):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.num_seconds = num_seconds
        self.found_bssids = set()
        self.found_stas = set()

    def get_macs(self,pkt):
        if pkt[Dot11].subtype == 4 and pkt[Dot11].type == 0: # Probe Req
            self.found_stas.add(pkt[Dot11].addr2)
        elif pkt[Dot11].subtype == 8 and pkt[Dot11].type == 0:  # Beacon
            self.found_bssids.add(pkt[Dot11].addr2)

    def run(self):
        print("Scanning for BSSIDs and non-AP STA MAC addresses")
        sniff(iface=interface, prn=self.get_macs, store=0, filter="wlan type mgt subtype beacon or wlan type mgt subtype probe-req",timeout=self.num_seconds)

# Some data that we'll use
dt = 0
interval_seconds = 60
#interval_seconds = 30
#interval_seconds = 4
sleeptime = 10

# One run
ONE_RUN = False
if ONE_RUN:
    while True:
        global token

        token = struct.pack("B", dt)
        dt = (dt + 1) % 256
        testap = "\x24\xa4\x3c\x00\x00\x00"
        #send_wnm_eventreq(br, tplink, br)
        send_wnm_eventreq(testap, testap, br)
        #send_basic_req(testap, testap, br)
        #send_cca(testap, testap, br)
        #send_load_req(testap, testap, br)
        #send_statistics_req(testap, testap, br)
        #send_frame_req(testap, testap, br)
        #send_link_measurement(testap, testap, br)
        #send_basic_req(br, tplink, br)
        #send_load_req(br, tplink, br)
        #send_statistics_req(br, tplink, br)
        #send_cca(br, tplink, br)
        #send_frame_req(br, tplink, br)
        #send_link_measurement(br, tplink, br)
    exit()

# Multiple runs with state machine
# Scan for BSSIDs and non-AP STA MACs
b = MACScanner(interval_seconds * 2)
b.start()
b.join(interval_seconds)
bssids = b.found_bssids
stas = b.found_stas
pprint(bssids)
pprint(stas)

# Stimulus frames sniffer
s = Sniffer()
s.start()
start_time = time()

# TODO: Seq num for back req?
current_round = 0
ROUNDS = 5
experiment_total_start_time = time()
try:
    while True:
        global token
        global current_state
        global current_testcase
        global start_time

        token = struct.pack("B", dt)
        dt = (dt + 1) % 256

        current_function = state_actions[current_state]
        if current_testcase == TestCase.BROADCAST:
            arguments = {'bssid': br, 'src': tplink, 'dst': br }
            current_function(**arguments)
        elif current_testcase == TestCase.ZERO:
            arguments = {'bssid': zero, 'src': tplink, 'dst': br }
            current_function(**arguments)
        elif current_testcase == TestCase.BSSIDS:
            arguments = {'method': current_function, 'bssid_list': bssids, 'src': tplink, 'dst': br }
            send_multi_bssid(**arguments)
        elif current_testcase == TestCase.UNICAST:
            arguments = {'method': current_function, 'bssid': br, 'src': tplink, 'dst_list': stas }
            send_multi_unicast(**arguments)
        elif current_testcase == TestCase.MAX:
            current_state += 1
            if state_actions[current_state] == None:
                current_state = 0
                current_round += 1
                if current_round == ROUNDS:
                    break
            current_testcase = 0  # Back to square one
        else:
            print("Unkown testcase: " + str(current_testcase) + "! Exiting")
            exit()

        if time() - start_time > interval_seconds:
            sleep(sleeptime)
            current_testcase = current_testcase + 1
            start_time = time()

except KeyboardInterrupt:
    print("Caught CTRL+C! Saving to file...")

experiment_total_time = time() - experiment_total_start_time
# Write results to file
all_entries = []
with open("probeind_experiment_results.csv", "w") as f:
    for state in macs_seen_state:
        for entry in macs_seen_state[state]:
            if not entry.mac == "10:fe:ed:00:00:00":
                f.write(str(entry) + "\n")
            all_entries.append(entry.pkt)

print("\nCatted result:")
os.system("cat probeind_experiment_results.csv")
print("Creating pcap")
wrpcap("probeind_experiment_results.pcap", all_entries)

# Write includable data files
print("Creating includable data files")
os.system("mkdir -p latex")
with open("latex/probeind_d_num_bssids", "w") as f:
    f.write(str(len(bssids)))
with open("latex/probeind_d_stas", "w") as f:
    for sta in stas:
        f.write(str(sta) + "\n")
with open("latex/probeind_d_num_stas", "w") as f:
    f.write(str(len(stas) - 1))  # -1 because of our own MS MAC
with open("latex/probeind_d_total_time", "w") as f:
    f.write(str(experiment_total_time))
with open("latex/probeind_d_sleep_time", "w") as f:
    f.write(str(sleeptime))
with open("latex/probeind_d_interval_seconds", "w") as f:
    f.write(str(int(interval_seconds)))
for state in macs_seen_state:
    with open("latex/probeind_d_exp" + str(state) + "_vuln", "w") as f:
        if (state % TestCase.MAX) == TestCase.BSSIDS:  # No logged transmitter for BSSIDs
            f.write(str(len(macs_seen_state[state])))
        else: # Subtract transmitter frame from responding devices, because it is the transmitter itself
            f.write(str(len(macs_seen_state[state]) - 1))
