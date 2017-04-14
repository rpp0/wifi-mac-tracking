#!/usr/bin/env python2
# Author: Pieter Robyns, 2017
# License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
# See LICENSE in this Git repository for the full license description

from pymongo import ASCENDING, DESCENDING, MongoClient
from bson.binary import Binary
from scapy.all import Raw, RadioTap, Dot11
from scapy.fields import *
from scapy_tags import *
from scapy.layers.dot11 import Dot11Elt, Dot11ProbeReq
from prettytable import PrettyTable
from bson.objectid import ObjectId
from collections import defaultdict
from netaddr import *
from random import shuffle
from pprint import pprint
import numpy as np
import plotting
import scapy
import string
import bson
import sys
import time
import struct
import datetime
import hashlib
import itertools
import binascii
import math
import locale
import argparse

# Research center data: mac_research
# Glimps 2015 data: mac_info
arg_parser = argparse.ArgumentParser(description="Advanced MAC layer fingerprinter for Probe Request frames", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
arg_parser.add_argument('type', choices=['mongodb', 'file', 'pcap'])
arg_parser.add_argument('name', help='The path to / name of the dataset containing Probe Requests', choices=['mac_info','mac_research'])
arg_parser.add_argument('--host', dest='host', help='MongoDB host', default='localhost')
arg_parser.add_argument('--debug', '-d', dest='debug', help='Debug mode', action='store_true')
arg_parser.add_argument('--big-endian', dest='be', help='Big Endian Radiotap header', action='store_true')
arg_parser.add_argument('--train-samples', dest='num_train_samples', help='Number of training samples', type=int, default=30000)
arg_parser.add_argument('--test-samples', dest='num_test_samples', help='Number of test samples', type=int, default=50)
arg_parser.add_argument('--threshold', dest='threshold', help='Stability threshold', type=float, default=0.3)
args = arg_parser.parse_args()

if args.name == "mac_info":
    USE_RESEARCH_DATA = False
else:
    USE_RESEARCH_DATA = True

NUM_SAMPLES = args.num_train_samples
NUM_SAMPLES_TEST = args.num_test_samples # Number of MACs to fingerprint
NUM_SAMPLES_VARIABILITY = NUM_SAMPLES  # Number of MACs to analyze for variability
NUM_SAMPLES_STABILITY = NUM_SAMPLES  # Number of MACs to analyze for stabililty
HASH_PRINT_CUTOFF = 12  # Number of characters of hash to display
USE_HAMMING = False
HAMMING_TOLERANCE_STABLE = 8  # Tolerance for stable bits
HAMMING_TOLERANCE_UNSTABLE = 16  # Tolerance for unstable bits
THRESHOLD_VARIABILITY = 0.0
THRESHOLD_STABILITY = args.threshold  # Delete bits with entropy < v. Extreme: THRESHOLD_STABILITY = 1.0. Good value without MHEADER: 0.3
FILTERING_APPROACH = True  # Use filtering approach
USE_TRISTATE = True
GRAPHS = False     # Show graphs
FILE_BASED = False  # Read from research file instead of database DEPRECATED
DISSECT_ELTS = True
APPLY_FINGERPRINT_TO_DB = False  # Store fingerprint in database
INCLUDE_MHEADER = False
ONE_RUN = True
TOPHASH_APPROACH = False
VIS_XRANGE = [0, 255]
#VIS_XRANGE = [0, 500]
UNSTABLE_ELT_IDS = []

debug = False
last_time = 0
locale.setlocale(locale.LC_ALL, 'en_US.utf-8')

# Override default field descriptor
Dot11Elt.fields_desc = [ ByteEnumField("ID", 0, elt_id_map),
                         FieldLenField("len", None, "info", "B"),
                         StrLenField("info", "", length_from=lambda x:x.len) ]

def locale_number(number):
    return locale.format("%d", number, grouping=True)

# Collection of hashes constituting a fingerprint
class Hash():
    def __init__(self, bits, ts):
        h = b''.join(bits)
        if bits == []:
            self.hash = None
        else:
            self.hash = hashlib.sha256(h).hexdigest()
        self.ts = ts

    def __str__(self):
        return str(self.hash)[0:HASH_PRINT_CUTOFF] + " @ {timestamp:%a %d %H:%M:%S}".format(timestamp=self.ts)

    def __repr__(self):  # We use this for hash key representation
        if self.hash is None:
            return 'None'
        else:
            return self.hash

    def __hash__(self):
        return hash(self.hash)

    def __eq__(self, other):
        return self.hash == other.hash

class Fingerprint():
    def __init__(self):
        self.hash_occurences = defaultdict(lambda: 0.0)
        self.hash_occurences_hamming = defaultdict(lambda: 0.0)
        self.total_fingerprints = 0.0
        self.unstable_data = []
        self.stable_data = {}
        self._identifier = None  # If it's not a random MAC, we have a global identifier
        self._resolved = False

    def resolve(self, identifier):  # Set a global identifier
        if not identifier is None:
            self._resolved = True
            self._identifier = identifier
        else:
            self._identifier = repr(self.get_top_hash())

    def fingerprint(self):
        return self._identifier

    def add_hash_hamming(self, data, h):
        self.hash_occurences_hamming[h] += 1.0
        self.stable_data[data] = h  # Match hamming hash with data

    def add_hash(self, fp_hash):
        self.hash_occurences[fp_hash] += 1.0
        self.total_fingerprints += 1.0

    def add_unstable(self, unstable_data):
        for bits in unstable_data:
            if bits not in self.unstable_data:
                self.unstable_data.append(bits)

    def add_stable(self, stable_data):
        for elem in stable_data:
            if elem not in self.stable_data.keys():
                self.stable_data[elem] = None

    # If we have more than one hash for a MAC, it's not stable
    def is_stable(self):
        if len(self.hash_occurences.keys()) > 1.0:
            return False
        return True

    def is_stable_hamming(self):
        if len(self.hash_occurences_hamming.keys()) > 1.0:
            return False
        return True

    # Get the most likely hash based on all calculated hashes
    def get_top_hash(self):
        max_occ = 0.0
        best_h = None
        for h in self.hash_occurences.keys():
            if self.hash_occurences[h] > max_occ:
                max_occ = self.hash_occurences[h]
                best_h = h
        return best_h

    def get_fingerprint_hamming(self):
        max_occ = 0.0
        best_h = None
        for h in self.hash_occurences_hamming.keys():
            if self.hash_occurences_hamming[h] > max_occ:
                max_occ = self.hash_occurences_hamming[h]
                best_h = h
        return best_h


    # Stabililty is the most probable hash fingerprint that was determined for
    # this MAC.
    def get_stability(self):
        h = self.get_top_hash()
        return self.hash_occurences[h] / self.total_fingerprints

    def __str__(self):
        result = ""
        if self._resolved:
            result += str(self._identifier)
            h = self.get_top_hash()
            hash_occurence = self.hash_occurences[h] / self.total_fingerprints
            result += " ["
            result += str(h) + " (" + "{0:.2f}".format(hash_occurence) + ")"
            result += "]"
        else:
            for h in self.hash_occurences:
                hash_occurence = self.hash_occurences[h] / self.total_fingerprints
                result += "* " + str(h) + " (" + "{0:.2f}".format(hash_occurence) + "),"
        result += " !"
        for h in self.hash_occurences_hamming:
            result += str(h)[0:HASH_PRINT_CUTOFF] + ", "
        result += "+[" + str(sorted(self.unstable_data)) + "]"
        return result


# Collection of MAC - fingerprint pairs in dictionary
class FingerprintCollection():
    def __init__(self):
        self.fps = defaultdict(lambda: Fingerprint())
        self.total_macs = 0.0
        self.num_stable_macs = 0.0
        self.amt_stability = 0.0
        self.amt_stability_nr = 0.0
        self.hash_collisions = 0.0
        self.hash_collisions_nonrandom = 0.0
        self.fp_collisions = 0.0
        self.rand_macs = 0.0
        self.stability = 0.0
        self.hash_uniqueness = 0.0
        self.hash_uniqueness_nonrandom = 0.0
        self.fp_uniqueness = 0.0
        self.num_deanonymized = 0

        self.collisions_hamming = 0.0
        self.num_stable_macs_hamming = 0.0
        self.stability_hamming = 0.0
        self.uniqueness_hamming = 0.0
        self.num_deanonymized_hamming = 0
        self.stable_fps_hamming = {}

    def add_fp(self, mac, fp):
        self.fps[mac] = fp

    def add_hash(self, mac, fp_hash):
        self.fps[mac].add_hash(fp_hash)

    def add_unstable(self, mac, unstable_data):
        self.fps[mac].add_unstable(unstable_data)

    def add_stable(self, mac, stable_data):
        self.fps[mac].add_stable([stable_data])

    # For each MAC, determine hamming distance with all other MACs,
    # with a certain tolerance in errors for:
    #   a) Bits that should be stable (HAMMING_TOLERANCE_STABLE)
    #   b) Bits that should not be stable (HAMMING_TOLERANCE_UNSTABLE)
    # Then, groups fingerprints with similar hamming distance together
    # and create a unique ID for this group
    def determine_hamming_hashes(self):
        print("Starting hamming analysis")
        id_h = 0

        # Stable data hamming
        for mac1 in self.fps:
            # If this MAC has no hamming ID yet, generate one for it
            for stable_elem1 in self.fps[mac1].stable_data:
                # If we already calculated the hamming distance before, leave it
                if not self.fps[mac1].stable_data[stable_elem1] is None:
                    continue

                hamming_h = hashlib.sha256(str(id_h)).hexdigest()
                self.fps[mac1].add_hash_hamming(stable_elem1, hamming_h)
                id_h += 1

                for mac2 in self.fps:
                    for stable_elem2 in self.fps[mac2].stable_data:
                        hamming_distance_stable = hamming_distance_bits(stable_elem1, stable_elem2)
                        if hamming_distance_stable <= HAMMING_TOLERANCE_STABLE:
                            self.fps[mac2].add_hash_hamming(stable_elem2, hamming_h)

        assert(not True in [None in x.hash_occurences_hamming for x in self.fps.values()])  # every entry should have a hamming hash

    def deanonymize(self):
        print("Deanonymizing...")

        macs_per_fp = defaultdict(lambda: [])
        for mac, fp in sorted(self.fps.items(), key=lambda (k,v): v.get_top_hash().ts):
            if not is_locally_administered_mac(mac):  # Set identifier of non-random MAC
                fp.resolve(mac)
            # Old approach
            #fp_top_hash = fp.get_top_hash()  # Get the most likely hash associated to it
            #macs_per_fp[fp_top_hash].append((mac, fp._resolved, fp_top_hash.ts))  # Append (mac, resolved, ts) tuple
            # New approach
            for fp_hash in fp.hash_occurences.keys():
                macs_per_fp[fp_hash].append((mac, fp._resolved, fp_hash.ts))

        for mac, fp in sorted(self.fps.items(), key=lambda (k,v): v.get_top_hash().ts):
            if not fp._resolved: # If not resolved, lookup closest fingerprint in time that is resolved
                # Count based approached
                if TOPHASH_APPROACH:
                    #print("Deanonymizing based on top occurring hash")
                    fp.resolve(self.find_best_hash([fp.get_top_hash()], macs_per_fp))
                else:
                    # Time based approach
                    #print("Deanonymizing based on nearest time hash")
                    fp.resolve(self.find_best_hash(fp.hash_occurences.keys(), macs_per_fp))

    def find_best_hash(self, hash_collection, lookup_table):
        best_td = sys.maxint
        best_id = None
        for fp_hash in hash_collection:
            our_timestamp = fp_hash.ts
            to_search = lookup_table[fp_hash]
            for e in to_search:
                if e[1]: # Resolved
                    td = abs((our_timestamp - e[2]).total_seconds()) # ts
                    if td < best_td:
                        best_td = td
                        best_id = e[0] # Mac
        return best_id

    def analyze(self):
        if USE_HAMMING:
            self.determine_hamming_hashes()
        self.total_macs = float(len(self.fps.keys()))

        for mac, fp in sorted(self.fps.items(), key=lambda (k,v): (v.fingerprint(), v.get_top_hash().ts)):
            is_random_mac = is_locally_administered_mac(mac)
            resolved = fp._resolved
            # If local mac got resolved, it's deanonymized
            if is_random_mac:
                self.rand_macs += 1
                if resolved:
                    self.num_deanonymized += 1
            print(self.beautify(mac, fp))

        # Stability
        # Normal
        for mac in self.fps:
            fp = self.fps[mac]
            is_random_mac = is_locally_administered_mac(mac)

            if fp.is_stable():
                self.num_stable_macs += 1.0
                assert(len(fp.hash_occurences.keys()) == 1)

            if not is_random_mac:
                self.amt_stability_nr += fp.get_stability()
            self.amt_stability += fp.get_stability()
        self.stability = self.num_stable_macs / self.total_macs
        self.amt_stability /= self.total_macs
        self.amt_stability_nr /= (self.total_macs - self.rand_macs)

        self.stability_hamming = self.num_stable_macs_hamming / self.total_macs

        # Uniqueness among stable fps
        # and deanonimyzation
        # Normal
        seen_h = set()
        seen_fp = set()
        for mac in self.fps:
            fp = self.fps[mac]
            h = fp.get_top_hash()
            f = fp.fingerprint()
            is_random_mac = is_locally_administered_mac(mac)
            resolved = fp._resolved

            # Calc hash collisions for all macs
            if repr(h) in seen_h:
                self.hash_collisions += 1
                if not is_random_mac:
                    self.hash_collisions_nonrandom += 1
            else:
                seen_h.add(repr(h))

            # Same for fps
            if f in seen_fp:
                if not resolved:
                    self.fp_collisions += 1
            else:
                seen_fp.add(f)

        self.hash_uniqueness = (self.total_macs - self.hash_collisions) / self.total_macs
        self.hash_uniqueness_nonrandom = (self.total_macs - self.rand_macs - self.hash_collisions_nonrandom) / (self.total_macs - self.rand_macs)
        self.fp_uniqueness = (self.total_macs - self.fp_collisions) / self.total_macs

        # Print analysis
        print("\n\nStrict hash stability: " + str(self.stability * 100.0) + "%")
        print("Real hash stability: " + str(self.amt_stability * 100.0) + "%")
        print("Real hash stability (non-random): " + str(self.amt_stability_nr * 100.0) + "%")
        print("Hash uniqueness: " + str(self.hash_uniqueness * 100.0) + "%")
        print("Hash uniqueness (non-random): " + str(self.hash_uniqueness_nonrandom * 100.0) + "%")
        print("Fingerprint uniqueness: " + str(self.fp_uniqueness * 100.0) + "%")
        if self.rand_macs > 0:
            print("Deanonymized MACs: " + str(self.num_deanonymized) + " / " + str(self.rand_macs) + " (" + str(self.num_deanonymized / self.rand_macs * 100.0) + "%)")
        print("Total MACs: " + str(self.total_macs))

    def apply(self, control=False):
        suffix = "_nr" if control else ""
        db_fps = db.wt_taudb_remote['fingerprints_' + args.name + suffix]

        print("\nReversing dictionary...")
        v = defaultdict(lambda: [])
        for key, value in sorted(self.fps.iteritems()):
            fp_str = value.fingerprint()
            if key not in v[fp_str]:
                v[fp_str].append(key)

        print("Applying fingerprints...")
        db.wt_taudb_remote['fingerprints_' + args.name + suffix].remove({})
        done = 0
        total = len(self.fps)
        for fp in v:
            mac_list = v[fp]
            db_fps.insert_one({'fp': fp, 'macs': mac_list})
            done += 1
            print_status(done, total)
        print("Done!")

    def beautify(self, mac, fp):
        prefix = "(!) " if is_locally_administered_mac(mac) else "    "
        return prefix + mac_and_oui(str(mac)) + " => " + str(fp)

def mac_and_oui(mac):
    oui = "unknown"
    try:
        oui = EUI(mac).oui.registration().org
        if oui == "":
            oui = "unknown"
    except Exception, e:
        pass
    return "{0:<7s} {1:<20s}".format(mac, '(' + oui[0:18] + ')')


class MongoHandler():
    def __init__(self, start_id, end_id):
        self.mongo_client_remote = MongoClient(args.host)
        self.start_id = start_id
        self.end_id = end_id

        # Select db
        if USE_RESEARCH_DATA:
            print("Using research center data")
        self.wt_taudb_remote = self.mongo_client_remote.anonymized

    def get_data(self):
        if args.type == 'file':
            return FileParser(args.name).parse()
        else:
            if USE_RESEARCH_DATA:
                return self.wt_taudb_remote[args.name].find({"_id": {"$gte": self.start_id, "$lte": self.end_id}})
            else:
                return self.wt_taudb_remote.mac_info.find({"_id": {"$gte": self.start_id, "$lte": self.end_id}})

# Record containing MAC address and list of fields raw data for one Probe
class DatasetRecord():
    def __init__(self, mac, ts):
        self.mac_addr = mac
        self.ts = ts
        self.fields = []

    def add_field(self, tag, field):
        self.fields.append( (tag,field) )

class FileParser():
    def __init__(self, path):
        self.path = path
        self.num_records = 0
        self.f = None
        self.records = []
        self.index = 0

    def read_record_one(self, length, returntype='B'):
        raw = self.read_record_raw(length)

        return struct.unpack(returntype, raw)[0]

    def read_record_raw(self, length):
        raw = self.f.read(length)
        if not raw:
            raise EOFError

        return raw

    def count(self):
        return self.num_records

    def __iter__(self):
        return self

    def next(self):
        result = None

        try:
            result = self.records[self.index]
        except IndexError:
            raise StopIteration

        self.index += 1

        return result

    def parse(self):
        self.f = open(self.path, "rb")

        while True:
            # Read one probe
            probe = {}
            try:
                # MAC address TLV
                pkt_mac_type = self.read_record_one(1, 'B')
                assert(pkt_mac_type == 1)
                pkt_mac_len = self.read_record_one(2, '>H')  # Big endian, since it comes from MIPS device
                assert(pkt_mac_len == 6)
                pkt_mac = self.read_record_raw(pkt_mac_len)
                assert(len(pkt_mac) == 6)
                probe['mac_addr'] = binascii.hexlify(pkt_mac)

                # Capabilities TLV
                pkt_ie_type = self.read_record_one(1, 'B')
                assert(pkt_ie_type == 2)
                pkt_ie_len = self.read_record_one(2, '>H')
                pkt_ie = self.read_record_raw(pkt_ie_len)
                assert(len(pkt_ie) == pkt_ie_len)
                probe['info'] = pkt_ie

                # Add to records
                self.records.append(probe)
                self.num_records += 1
            except EOFError:
                break

        self.f.close()
        return self

# Parse information elements from MongoDB with scapy and convert to raw bytes.
# Then randomize the sample order and get some properties such as the max
# number of cols, the number of rows, etc.
class Dataset():
    def __init__(self, mongocursor, num_samples=NUM_SAMPLES_TEST, skip_local=True, do_shuffle=True):
        self.total_rows = mongocursor.count()
        self.max_rows_per_elt = defaultdict(lambda: 0)  # Number of entries per information element
        self.max_cols_per_elt = defaultdict(lambda: 0)  # Length in bytes of longest information element per information element type
        self.records = []

        print("Preprocessing...")
        done = 0
        limit = num_samples

        macs_seen = set()

        for element in mongocursor:
            # Get data from Mongo
            bin_data = element['info']
            mac_addr = element['mac_addr']
            ts = element['_id'].generation_time
            macs_seen.add(mac_addr)

            if skip_local and is_locally_administered_mac(mac_addr):
                continue  # Do not train on locally adm MAC addresses

            # Store in our own record
            r = DatasetRecord(mac_addr, ts)

            # Loop over each information element in the binary data
            if DISSECT_ELTS:  # Go over each element ID seperately
                err = self.dissect_frame(bin_data, r)
                if(err):
                    continue
            else:  # Consider probe in entierety
                if bin_data[4:6] == "\x2f\x40":
                    if args.be:
                        # Reverse endianess for sensor provided radiotap header
                        bin_data = bin_data[0:2] + bin_data[3] + bin_data[2] + bin_data[4:-4]

                    # Let Scapy dissect the packet
                    elt = RadioTap(bin_data)

                    # Exclude MAC
                    elt[Dot11].addr1 = '\x00\x00\x00\x00\x00\x00'
                    elt[Dot11].addr2 = '\x00\x00\x00\x00\x00\x00'
                    elt[Dot11].addr3 = '\x00\x00\x00\x00\x00\x00'
                    elt = str(elt)
                else:
                    elt = Dot11Elt(bin_data)
                elt_id = b'\xff'  # Special elt id indicating whole frame
                raw_ie_bytes = elt_id + str(elt)
                r.add_field(elt_id, raw_ie_bytes)
                self.max_rows_per_elt[elt_id] += 1
                self.max_cols_per_elt[elt_id] = max(self.max_cols_per_elt[elt_id], len(raw_ie_bytes))


            # Add our record to the dataset
            self.records.append(r)
            done = len(macs_seen)
            print_status(done, self.total_rows)

            if limit != -1 and done >= limit:
                break

        if do_shuffle:
            shuffle(self.records)
        print("Dataset contains " + str(len(self.records)) + " records")

    def add_to_record(self, r, raw_bytes):
        raw_bytes_len = len(raw_bytes)

        if raw_bytes_len > 0:
            field_id = raw_bytes[0]

            # Add element to our record
            r.add_field(field_id, raw_bytes)

            # Gather some info about the element TODO refactor me duplicate code
            self.max_rows_per_elt[field_id] += 1
            self.max_cols_per_elt[field_id] = max(self.max_cols_per_elt[field_id], raw_bytes_len)
        else:
            print("Found field without ID. Definitely shouldn't happen. Scapy bug?")
            exit()

    def dissect_frame(self, frame, r):
        if frame[4:6] == "\x2f\x40":
            if args.be:
                # Reverse endianess for sensor provided radiotap header (which is Big Endian)
                frame = frame[0:2] + frame[3] + frame[2] + frame[4:-4]
            frame = RadioTap(frame)
            if not Dot11 in frame:
                return True
            if frame[Dot11].type != 0 or frame[Dot11].subtype != 4:
                return True
            frame[Dot11].addr1 = '\x00\x00\x00\x00\x00\x00'
            frame[Dot11].addr2 = '\x00\x00\x00\x00\x00\x00'
            frame[Dot11].addr3 = '\x00\x00\x00\x00\x00\x00'
        else:
            frame = Dot11Elt(frame)

        # Copy of full frame for debugging
        #ff = frame.copy()

        # An array containing the order of information elements for this frame
        elt_order_bytes = b"\xfd"

        # Dissect layers with Scapy
        while type(frame) != scapy.packet.NoPayload:
            layer = frame.copy()
            layer.remove_payload()
            raw_bytes = str(layer)

            if type(layer) is scapy.layers.dot11.Dot11 and INCLUDE_MHEADER:
                # Artificially add field ID for MAC header
                raw_bytes = "\xfe" + raw_bytes
                self.add_to_record(r, raw_bytes)
            elif type(layer) is scapy.layers.dot11.Dot11Elt:
                elt_id = raw_bytes[0]
                self.add_to_record(r, raw_bytes)
                elt_order_bytes += elt_id

            # Go to next layer
            frame = frame.payload

        # Add order of information elements as custom field
        if len(elt_order_bytes) > 1:
            self.add_to_record(r, elt_order_bytes)

        return False


def determine_max_bits_per_elt(dataset):
    result = {}

    for elem in dataset.max_cols_per_elt:
        result[elem] = dataset.max_cols_per_elt[elem] * 8

    return result

class EltBitFrequencyTable():
    def __init__(self, maximum_bits_per_elt):
        self.data = {}
        self.probability_matrix = {}
        self.columns = 0
        self.rows = 0
        self.maximum_bits_per_elt = maximum_bits_per_elt

    def clear(self):
        self.data = {}
        self.probability_matrix = {}
        self.columns = 0
        self.rows = 0
        self.maximum_bits_per_elt = {}

    def add(self, elt_id, bit_idx, bit_val):
        if not elt_id in self.data:
            self.data[elt_id] = []

        if bit_idx < len(self.data[elt_id]) and bit_idx >= 0:
            self.data[elt_id][bit_idx] += str(bit_val)
        else:
            self.data[elt_id].insert(bit_idx, str(bit_val))
        assert(self.data[elt_id][bit_idx][-1] == str(bit_val))

    # Bytes are stored in Big Endian, left to right e.g.
    # \x80\x01 is stored as 10000000 00000001
    def add_byte(self, elt_id, byte_idx, byte_val):
        byte_as_int = struct.unpack('B', byte_val)[0]
        for i in range(0,8):
            idx = (byte_idx * 8) + i
            val = "0"
            if byte_as_int & (0x80 >> i) > 0:
                val = "1"

            self.add(elt_id, idx, val)

    def add_field(self, tag, field):
        field_num_bytes = len(field)

        # Fill bits at correct locations
        for i in range(0, field_num_bytes):
            self.add_byte(tag, i, field[i])

        # Fill empty spaces with 'x'
        if USE_TRISTATE:
            for i in range(field_num_bytes * 8, self.maximum_bits_per_elt[tag]):
                self.add(tag, i, 'x')

    def __str__(self):
        return str(self.data)

    # Entropy value between 0 and 1
    def _check_probability(self, target):
        diff = 0
        probs = {"0": 0.0, "1": 0.0, "x": 0.0}
        length = len(target)

        if length < 1:
            return 0

        for i in range(0, length):
            probs[target[i]] += 1.0

        h = 0
        for key in probs:
            px = probs[key] / length
            if px != 0:
                h += px * math.log(px, len(probs.keys()))

        #print(str(probs) + " -> " + str(-h))

        return (-h)

    def visualize(self, inverted=False, show=GRAPHS, name='heatmap.pdf'):
        if self.probability_matrix != {}:
            plotting.make_heatmap(self.probability_matrix, VIS_XRANGE, inverted=inverted, show=show, name=name)

    def analyze_elt_id_uniqueness(self, display=True):
        # Determine matrix columns
        max_cols = 0
        for elt_id in self.data:
            max_cols = max(max_cols, len(self.data[elt_id]))
            self.columns = max_cols

        # Prepare data structures
        cols = ["Element name"]
        for i in range(0, max_cols):
            cols.append("Bit " + str(i))
        print_table = PrettyTable(cols)
        print_table.padding_width = 1

        for elt_id in self.data:
            # Human readable elt_id?
            name = human_readable_elt(ord(elt_id))
            if name == "Nonexistent":
                if ord(elt_id) < 253 or ord(elt_id) == 254 or ord(elt_id) == 255:
                    print("Warning: non-existent elt_id " + str(ord(elt_id)))
                    continue

            # Generate row
            row = [name] + [0] * max_cols

            # Calculate probability of a 0 or 1 for each bit
            for i in range(0, len(self.data[elt_id])):
                bit = self.data[elt_id][i]
                prob = self._check_probability(bit)
                row[i+1] = prob  # +1 since first row is the elem name

            print_table.add_row(row)
            self.probability_matrix[ord(elt_id)] = row[1:]
            self.rows += 1

        if display:
            #print("Writing to file")
            #with open("results.txt", "w") as f:
            #    f.write(str(print_table) + "\n")

            self.visualize(name='variability.pdf')


    def test(self):
        self.clear()
        self.maximum_bits_per_elt['\x00'] = 3 * 8
        self.maximum_bits_per_elt['\x01'] = 2 * 8
        test_data = [
            "\x00\x80",
            "\x00\x00",
            "\x00\x00",
            "\x00\x01",
            "\x00\x01",
            "\x00\x01",
            "\x01\x01",
            "\x00\x00\x03",
        ]
        control = {
            '\x00': [
                # Byte 0
                "0000000", # 0
                "0000000", # 1
                "0000000", # 2
                "0000000", # 3
                "0000000", # 4
                "0000000", # 5
                "0000000", # 6
                "0000000", # 7
                # Byte 1
                "1000000", # 0
                "0000000", # 1
                "0000000", # 2
                "0000000", # 3
                "0000000", # 4
                "0000000", # 5
                "0000000", # 6
                "0001110", # 7
                # Byte 3
                "0", # 0
                "0", # 1
                "0", # 2
                "0", # 3
                "0", # 4
                "0", # 5
                "1", # 6
                "1", # 7
            ],
            '\x01': [
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "1",
                #
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "1",
            ]
        }
        control_tristate = {
            '\x00': [
                # Byte 0
                "0000000", # 0
                "0000000", # 1
                "0000000", # 2
                "0000000", # 3
                "0000000", # 4
                "0000000", # 5
                "0000000", # 6
                "0000000", # 7
                # Byte 1
                "1000000", # 0
                "0000000", # 1
                "0000000", # 2
                "0000000", # 3
                "0000000", # 4
                "0000000", # 5
                "0000000", # 6
                "0001110", # 7
                # Byte 3
                "xxxxxx0", # 0
                "xxxxxx0", # 1
                "xxxxxx0", # 2
                "xxxxxx0", # 3
                "xxxxxx0", # 4
                "xxxxxx0", # 5
                "xxxxxx1", # 6
                "xxxxxx1", # 7
            ],
            '\x01': [
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "1",
                #
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "0",
                "1",
            ]
        }

        if USE_TRISTATE:
            control = control_tristate

        for elem in test_data:
            self.add_field(elem[0], elem)

        errors = 0

        # Check values
        for key in control:
            byte_array = control[key]
            for byte_idx in range(0, len(byte_array)):
                bit_array = byte_array[byte_idx]
                for bit_idx in range(0, len(bit_array)):
                    if bit_array[bit_idx] != self.data[key][byte_idx][bit_idx]:
                        errors += 1

        if errors > 0:
            print("Unit test EltBitFrequencyTable failed with " + str(errors) + " errors")
            print("Got:")
            print(self.data)
            print("Expected:")
            print(control)
            exit()
        self.clear()

# Preliminary stuff
t = EltBitFrequencyTable([])
t.test()
# Get objects from database
if USE_RESEARCH_DATA:
    from_time = datetime.datetime(2016, 1, 28, 15, 0, 0)
    to_time = datetime.datetime(2016, 2, 8, 12, 0, 0)
else:
    from_time = datetime.datetime(2015, 12, 10, 0, 0, 0)# -     datetime.timedelta(mins=mins)
    to_time = datetime.datetime(2015, 12, 12, 23, 59, 59)# - datetime.timedelta(mins=mins)
#from_time = datetime.datetime(2013, 1, 1)
from_dummy_id = ObjectId.from_datetime(from_time)
to_dummy_id = ObjectId.from_datetime(to_time)
db = MongoHandler(from_dummy_id, to_dummy_id)

def field_str(pkt, attr):
    fld,v = pkt.getfield_and_val(attr)
    return fld.i2repr(pkt, v)

def print_status(done, total):
    global last_time  #

    current_time = time.time()
    if int(current_time * 10) > int(last_time * 10):
        print("\r%d / %d                                             " % (done, total)),
        sys.stdout.flush()
    last_time = current_time

"""
Experiment 1
Calculate the variability of all bits in a specific element ID sent by all
stations. This gives a per elt indication of which bits are the most variable and
therefore have the most potential to become unique identifiers. We only consider
one probe request (collection of IDs) per MAC address to prevent that one "talkative"
MAC causes the variability of an elt to be underestimated: analogous to fingerprinting
different people in a room instead of the same one over and over again.

Assumptions: - Element ID of same kind remains the same
             - Probe request of the same MAC remains the same
"""
def do_experiment_1(dataset):
    processed_macs = set()

    frequencies = EltBitFrequencyTable(determine_max_bits_per_elt(dataset))
    done = 0
    total = dataset.total_rows

    print("\nDetermining variability...")
    for r in dataset.records:
        if r.mac_addr in processed_macs:
            continue  # Go to next probe so that one prevalent MAC can't bias the results

        for field_tuple in r.fields:
            frequencies.add_field(field_tuple[0], field_tuple[1])

        # Ignore this MAC in the future
        processed_macs.add(r.mac_addr)
        done += 1
        print_status(done, total)

    print("\nUnique MACs processed: " + str(len(processed_macs)))
    frequencies.analyze_elt_id_uniqueness()

    return frequencies

# Pad a list with certain value up to size
def pad_list(target, size, value=0.0):
    result = target + ([value] * (size-len(target)))
    assert(len(result) == size)
    return result

"""
Combine multiple frequency tables and calculate their average probabilities
"""
def calculate_average_frequency_table(frequency_tables):
    # Which freq table has the highest number of columns?
    print("Getting column dimensions")
    max_cols = 0
    for f in frequency_tables:
        max_cols = max(f.columns, max_cols)

    temp = defaultdict(lambda: [])

    # Make dictionary where keys are elt_ids and values
    # are the bit probabilities. Also, pad a row to
    # match max_cols. Multiple values (rows) per key are stored
    # in a list.
    for i in range(0, len(frequency_tables)):
        probability_matrix = frequency_tables[i].probability_matrix
        for key in probability_matrix.keys():
            temp[key].append(pad_list(probability_matrix[key], max_cols))
            del frequency_tables[i].probability_matrix[key]

    del frequency_tables

    # For every elt_id, average all probability rows
    final_data = {}
    for elt in temp:
        avg = np.zeros(max_cols)
        num_elems = 0
        print("Averaging probabilities for " + str(elt))

        for probabilities in temp[elt]:
            v = np.array(probabilities)
            avg += v
            num_elems += 1

        avg = avg / num_elems
        #print(avg)
        final_data[elt] = avg.tolist()

    print("Done")
    return final_data

# Function that removes fields which occur only once from a list
def filter_single_fields(field_list):
    field_dict = defaultdict(lambda: [])

    for field in field_list:
        field_id = field[0]
        field_dict[field_id].append(field[1])

    result = []
    for x in field_dict:
        if len(field_dict[x]) > 1:
            for v in field_dict[x]:
                result.append( (x, v) )
    return result

"""
Experiment 2:
For each MAC address with more than one capability of the same type, check
which bits of that capability element change or remain the same.
Aggregate results in an average probability matrix per bit per elt ID.
"""
def do_experiment_2(dataset):
    fields_per_mac = defaultdict(lambda: [])
    frequency_tables = []
    orders_per_mac = defaultdict(lambda: []) #Test

    maximum_bits_per_elt = determine_max_bits_per_elt(dataset)

    done = 0
    total = dataset.total_rows
    print("\nMerging elts per MAC...")
    for r in dataset.records:
        # Add elt to MAC address dict
        fields_per_mac[r.mac_addr].extend(r.fields)

        #Test
        for f in r.fields: #Test
            if f[0] == "\xfd": #Test
                orders_per_mac[r.mac_addr].append((f[1])) # Test

        done += 1
        print_status(done, total)

    # Show different orders
    #for mac in orders_per_mac:
    #    print(mac + ": " + str(set(orders_per_mac[mac])))

    done = 0
    total = len(fields_per_mac)
    print("\nCalculating stability...")
    for mac in fields_per_mac:
        # Filter elements that had only one occurence. Those cannot be compared
        filtered_fields = filter_single_fields(fields_per_mac[mac])

        if filtered_fields == []:
            continue

        frequencies = EltBitFrequencyTable(maximum_bits_per_elt)
        for field_tuple in filtered_fields:
            frequencies.add_field(field_tuple[0], field_tuple[1])

        # Calculate bit probability matrix and add table to frequencies
        frequencies.analyze_elt_id_uniqueness(display=False)
        frequency_tables.append(frequencies)
        done += 1
        print_status(done, total)

    print("\nUnique MACs processed: " + str(len(fields_per_mac.keys())))
    del fields_per_mac

    # Average all calculated probability matrices to get final result
    final_data = calculate_average_frequency_table(frequency_tables)
    #print(final_data)
    avg_frequencies = EltBitFrequencyTable(maximum_bits_per_elt)
    avg_frequencies.probability_matrix = final_data
    avg_frequencies.visualize(name='stability.pdf')

    return avg_frequencies

# Given a probability matrix for stability and variability, calculate which
# bits should be most suitable for use in a fingerprint
def optimal_fingerprinting_bits(stab_prob, vari_prob, filtering_approach=FILTERING_APPROACH):
    result = {}
    np.set_printoptions(threshold=np.nan)

    for key in vari_prob.probability_matrix:
        try:
            if filtering_approach:
                v = np.array(vari_prob.probability_matrix[key]) # Maximum entropy is optimal
                any_invariability = v < THRESHOLD_VARIABILITY
                v[any_invariability] = 0.0

                s = (1 - np.array(stab_prob.probability_matrix[key]))
                any_instability = s < THRESHOLD_STABILITY  # Any entropy in stability is bad
                s[any_instability] = 0.0
                any_stability = (any_instability == False)
                s[any_stability] = 1.0
                r = np.multiply(v,s)
            else:
                v = np.array(vari_prob.probability_matrix[key])
                s = (1 - np.array(stab_prob.probability_matrix[key]))  # Scale so that a bit with 1.0 entropy becomes worthless
                r = np.multiply(v,s)
            result[key] = r
        except KeyError as e:
            print("Skipping " + str(key) + " because it has not enough data to determine variability")
            pass

    suitable_bits = EltBitFrequencyTable([])
    suitable_bits.probability_matrix = result

    return suitable_bits

# If the score of a bit, given by the "probability" matrix is larger than threshold,
# set a mask value to true in the result. Return this mask for the entire collection
# of elt_ids in a matrix, while excluding elt_ids listed in "exclude".
def get_bitmask_per_elt(optimal_bits, threshold=0.0, exclude=[]):
    result = {}
    for key in optimal_bits.probability_matrix:
        if key not in exclude:
            probs = np.array(optimal_bits.probability_matrix[key])
            mask = probs > threshold
            result[key] = mask

    return result

# Convert an array of bytes to a binary string of 0s and 1s
# The MSB comes first in every byte
def bytes_to_bit_array(byte_array):
    result = ""
    for byte_val in byte_array:
        byte_as_int = struct.unpack('B', byte_val)[0]
        for i in range(0,8):
            val = "0"
            if byte_as_int & (0x80 >> i) > 0:
                val = "1"

            result += val
    return result

def hamming_distance_bits(bit_string_1, bit_string_2):
    b1l = len(bit_string_1)
    b2l = len(bit_string_2)
    maxlen = max(b1l, b2l)
    errors = 0

    for i in range(0, maxlen):
        if i >= b1l or i >= b2l:
            errors += 1
        else:
            if bit_string_1[i] != bit_string_2[i]:
                errors += 1

    return errors

def hamming_distance_bytes(byte_array_1, byte_array_2):
    bs1 = bytes_to_bit_array(byte_array_1)
    bs2 = bytes_to_bit_array(byte_array_2)

    return hamming_distance_bits(bs1, bs2)

assert(hamming_distance_bits("101", "1") == 2)
assert(hamming_distance_bits("1010", "1010") == 0)
assert(hamming_distance_bits("1010", "1011") == 1)
assert(hamming_distance_bits("1011", "1010") == 1)
assert(hamming_distance_bits("0", "1010") == 4)
assert(hamming_distance_bits("1", "1010") == 3)
assert(hamming_distance_bytes(b"\x01", b"\x00") == 1)

# Is it a locally administered (random) MAC?
def is_locally_administered_mac(mac_addr):
    # MAC address is stored as a string
    msb_str = mac_addr[0:2]
    msb = int(msb_str, 16)
    # Return the value of the second-least-significant bit
    return ((msb // 2) % 2) == 1

"""
Experiment 3:
Calculate a fingerprint for every MAC address and see
how often we were able to get a unique fingerprint and
whether the fingerprint remained stable.
"""
def calculate_fingerprint_efficiency(dataset, mask, unstable_elt_ids):
    fingerprints_per_mac = FingerprintCollection()

    done = 0
    total = dataset.total_rows

    print("\nDetermining fingerprints for random set of MACs...")
    for r in dataset.records:
        unstable_data = []
        fingerprint_bits = []
        # For every element ID, check if we have a bit mask.
        # If so, apply it and add the resulting bits to the fingerprint
        for field_tuple in r.fields:
            field_id_int = ord(field_tuple[0])
            raw_ie_bytes = field_tuple[1]

            if field_id_int in mask:
                bits = bytes_to_bit_array(raw_ie_bytes)
                bit_array = np.frombuffer(bits, dtype='uint8', count=len(bits), offset=0)
                mask_relevant = mask[field_id_int][0:len(bits)]
                sub_bits = bit_array[mask_relevant].tostring()
                if USE_TRISTATE:  # Add absence of bits if using tristate
                    sub_bits = sub_bits + (len(mask[field_id_int]) - len(sub_bits)) * 'x'

                fingerprint_bits.extend(sub_bits)  # Add bits to fingerprint profile
            elif field_id_int in unstable_elt_ids: # This element ID is inherently unstable / variable and should be aggregated over *multiple* probes instead of just one.
                unstable_data.append(raw_ie_bytes)

        done += 1
        print_status(done, total)

        # Create the fingerprint based on all gathered fingerprint bits
        #fingerprint_bits = list(mac_addr)  # Control test; should give 100% COMMENT ME
        fingerprints_per_mac.add_stable(r.mac_addr, ''.join(fingerprint_bits))  # TODO: Not used in last version of paper, can be removed
        fingerprints_per_mac.add_unstable(r.mac_addr, unstable_data) # TODO: Not used in last version of paper, can be removed
        fp_hash = Hash(fingerprint_bits, r.ts)
        fingerprints_per_mac.add_hash(r.mac_addr, fp_hash)

    # Deanonymize
    fingerprints_per_mac.deanonymize()

    if APPLY_FINGERPRINT_TO_DB:
        fingerprints_per_mac.apply()

    # Analyze how often we were right / wrong
    print("")
    fingerprints_per_mac.analyze()

    return fingerprints_per_mac

# Runs and results -----------------------------------------------------------------
assert(bytes_to_bit_array(b"\x80\x01") == "1000000000000001")
def do_run(dataset_v, dataset_s, dataset_test):
    # Calculate variability and stability
    variability = do_experiment_1(dataset_v)
    stability = do_experiment_2(dataset_s)

    # Determine optimal bits for fingerprint
    bits = optimal_fingerprinting_bits(stability, variability)
    bits.visualize(inverted=False, show=GRAPHS, name='optimal_bits.pdf')

    # Calculate mask based on optimal bits
    mask = get_bitmask_per_elt(bits, exclude=UNSTABLE_ELT_IDS, threshold=0.0)

    # Calculate fingerprint based on mask
    return calculate_fingerprint_efficiency(dataset_test, mask, UNSTABLE_ELT_IDS)

def write_results(results, num_samples, testnum_samples, f):
    global THRESHOLD_STABILITY

    variability = results.hash_uniqueness
    variability_nr = results.hash_uniqueness_nonrandom
    stability = results.amt_stability
    stability_nr = results.amt_stability_nr
    fp_uniqueness = results.fp_uniqueness
    deanon = results.num_deanonymized / results.rand_macs
    f.write("{0:.6f} {1:.6f} {2:.6f} {3:.6f} {4:.6f} {5:.6f} {6:.6f} {7:.6f} {8:.6f}\n".format(THRESHOLD_STABILITY, num_samples, testnum_samples, variability, variability_nr, stability, stability_nr, fp_uniqueness, deanon))
    f.flush()

def generate_datasets(vnum_samples, snum_samples, testnum_samples):
    elements = db.get_data()
    dataset_v = Dataset(elements, num_samples=vnum_samples)
    elements.rewind()
    dataset_s = Dataset(elements, num_samples=snum_samples)
    elements.rewind()
    dataset_test = Dataset(elements, skip_local=False, num_samples=testnum_samples)

    return dataset_v, dataset_s, dataset_test

# Experiments paper -----------------------------------------------------------------------------------------------------------
def compare_runs_lambda_small():
    global USE_RESEARCH_DATA

    NUM_SAMPLES = 100
    NUM_SAMPLES_TEST = NUM_SAMPLES
    NUM_SAMPLES_VARIABILITY = NUM_SAMPLES
    NUM_SAMPLES_STABILITY = NUM_SAMPLES
    USE_RESEARCH_DATA = True

    dataset_v, dataset_s, dataset_test = generate_datasets(NUM_SAMPLES_VARIABILITY, NUM_SAMPLES_STABILITY, NUM_SAMPLES_TEST)

    steps = 50
    one_step = 1.0 / steps
    print("Running multiple runs of " + str(NUM_SAMPLES) + " samples")
    with open('compared_runs_24may_lambda_small_research_ns.dat', 'w') as f:
        for i in range(0, steps+1):
            global THRESHOLD_VARIABILITY
            global THRESHOLD_STABILITY

            # Test parameters
            THRESHOLD_STABILITY = i * one_step

            # Other tests
            #NUM_SAMPLES = 5000
            #NUM_SAMPLES_TEST = int(i * one_step)
            #NUM_SAMPLES_VARIABILITY = NUM_SAMPLES
            #NUM_SAMPLES_STABILITY = NUM_SAMPLES
            print("Run: " + str(i * one_step))
            results = do_run(dataset_v, dataset_s, dataset_test)
            write_results(results, NUM_SAMPLES, NUM_SAMPLES_TEST, f)

def compare_runs_lambda():
    global USE_RESEARCH_DATA

    NUM_SAMPLES = 100000
    NUM_SAMPLES_VARIABILITY = NUM_SAMPLES
    NUM_SAMPLES_STABILITY = NUM_SAMPLES
    NUM_SAMPLES_TEST = NUM_SAMPLES
    USE_RESEARCH_DATA = True

    dataset_v, dataset_s, dataset_test = generate_datasets(NUM_SAMPLES_VARIABILITY, NUM_SAMPLES_STABILITY, NUM_SAMPLES_TEST)

    steps = 50
    one_step = 1.0 / steps
    print("Running multiple runs of " + str(NUM_SAMPLES) + " samples")
    with open('compared_runs_24may_lambda_research_ns.dat', 'w') as f:
        for i in range(0, steps+1):
            global THRESHOLD_VARIABILITY
            global THRESHOLD_STABILITY

            # Test parameters
            THRESHOLD_STABILITY = i * one_step

            # Other tests
            #NUM_SAMPLES = 5000
            #NUM_SAMPLES_TEST = int(i * one_step)
            #NUM_SAMPLES_VARIABILITY = NUM_SAMPLES
            #NUM_SAMPLES_STABILITY = NUM_SAMPLES
            print("Run: " + str(i * one_step))
            results = do_run(dataset_v, dataset_s, dataset_test)
            write_results(results, NUM_SAMPLES, NUM_SAMPLES_TEST, f)

def count_num_unique_probes_in_dataset(skip_local=True):
    elements = db.get_data()
    macs_seen = set()
    macs_seen_random = set()
    ies_seen = set()
    probes_seen = 0
    total = elements.count()
    done = 0

    for element in elements:
        # Get data from Mongo
        bin_data = element['info']
        mac_addr = element['mac_addr']

        macs_seen_random.add(mac_addr)

        if skip_local and is_locally_administered_mac(mac_addr):
            continue  # Do not train on locally adm MAC addresses

        # Determine if probe request
        if bin_data[4:6] == "\x2f\x40":
            if bin_data[38] == "\x40":
                bin_data = bin_data[62:]  # Cut header
                bin_data = bin_data[:-4]  # Cut CRC
                probes_seen += 1

                # Hash information elements
                ie_hash = hashlib.sha256(str(bin_data)).hexdigest()
                ies_seen.add(ie_hash)

            # Reverse endianess for sensor provided radiotap header
            #bin_data = bin_data[0:2] + bin_data[3] + bin_data[2] + bin_data[4:-4]
            #bin_data = RadioTap(bin_data)
            #if not Dot11 in bin_data:
                #continue
            #if bin_data[Dot11].type != 0 or bin_data[Dot11].subtype != 4:
                #continue
            #hexdump(bin_data)
            #bin_data = bin_data[Dot11Elt]
        else:
            probes_seen += 1

            # Hash information elements
            ie_hash = hashlib.sha256(str(bin_data)).hexdigest()
            ies_seen.add(ie_hash)

        macs_seen.add(mac_addr)

        done += 1
        print_status(done, total)

    suffix = ""
    if USE_RESEARCH_DATA:
        suffix = "_research"

    with open("latex/elt_byte_num_macs" + suffix, "w") as f:
        str_macs_seen = locale_number(len(macs_seen))
        print("Found " + str_macs_seen + " unique macs")
        f.write(str_macs_seen)
    with open("latex/elt_byte_num_macs_random" + suffix, "w") as f:
        str_macs_seen_random = locale_number(len(macs_seen_random))
        print("Found " + str_macs_seen_random + " unique macs (including random)")
        f.write(str_macs_seen_random)
    with open("latex/elt_byte_num_probes" + suffix, "w") as f:
        str_probes_seen = locale_number(probes_seen)
        print("Found " + str_probes_seen + " probe requests")
        f.write(str_probes_seen)
    with open("latex/elt_byte_num_ies" + suffix, "w") as f:
        str_ies_seen = locale_number(len(ies_seen))
        print("Found " + str_ies_seen + " unique ie sets")
        f.write(str_ies_seen)

# Since the heatmaps are generated seperately we define this function to merge
# their output in a single LaTeX table automatically
def merge_heatmap_tables(table_list, output):
    result = defaultdict(list)
    for table in table_list:
        with open(table, "r") as t:
            data = t.readlines()
            for line in data:
                s = line.split("&")
                key = s[0].strip()
                value = s[1].replace("\\", "").strip()
                result[key].append(value)

    with open(output, "w") as f:
        for key in sorted(result.keys()):
            line = key + " & "
            for entry in result[key]:
                line += entry + " & "
            line = line[:-2]
            f.write(line + "\\\\\n")

if __name__ == "__main__":
    # Set to True to count number of unique probes in dataset
    if False:
        print("Counting number of unique probes in dataset")
        count_num_unique_probes_in_dataset()
        exit()

    if ONE_RUN:
        elements = db.get_data()
        dataset_v = Dataset(elements, num_samples=NUM_SAMPLES_VARIABILITY)
        elements.rewind()
        dataset_s = Dataset(elements, num_samples=NUM_SAMPLES_STABILITY)
        elements.rewind()
        dataset_test = Dataset(elements, skip_local=False, num_samples=NUM_SAMPLES_TEST)
        do_run(dataset_v, dataset_s, dataset_test)
        merge_heatmap_tables(["latex/elt_entropy_table_variability.pdf", "latex/elt_entropy_table_stability.pdf"], "latex/elt_entropy_table")
    else:
        compare_runs_lambda()
# -----------------------------------------------------------------
