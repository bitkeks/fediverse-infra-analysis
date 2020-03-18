"""
Mastodon infrastructure analysis tool. See README for usage.
Copyright 2020 Dominik Pataky <dev@bitkeks.eu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import csv
import gzip
import ipaddress
import json
import os.path
import hashlib

from tqdm import tqdm

ipaddressified_ip_networks = {}


def ipaddressify_ip_networks(ip_networks: list) -> list:
    # print("Converting ip_networks to list with ipaddress.ip_address objects")
    new_ip_networks = []
    for entry in ip_networks:
        entry["start"] = ipaddress.ip_address(entry["start"])
        entry["end"] = ipaddress.ip_address(entry["end"])
        new_ip_networks.append(entry)
    return new_ip_networks


def asnfile_init(filename: str) -> dict:
    ip_networks = {}

    if not os.path.exists(filename):
        raise FileNotFoundError

    # Check hash of cache file
    filehash = hashlib.sha1()
    with open(filename, 'rb') as fh:
        while True:
            data = fh.read(65536)  # read in 64kb chunks
            if not data:
                break
            filehash.update(data)

    # construct file name from hash
    cachefile = ".asnfile_cached_{}.gz".format(filehash.hexdigest())

    if os.path.exists(cachefile):
        with gzip.open(cachefile, "rt") as fh:
            # print("Using cached parsing result")
            return json.load(fh)["ip_networks"]

    if filename.endswith(".gz"):
        fh = gzip.open(filename, "rt")
    else:
        fh = open(filename, "r")

    tsv = csv.reader(fh, delimiter="\t")

    # Using slices to chop up >400.000 entries which would later need to be iterated in whole
    current_slice = None
    current_slice_size = 0

    for row in tqdm(tsv, desc="Parsing entries in AS file {}".format(filename)):
        if current_slice is None:
            # Initialization
            current_slice = row[0]

        if current_slice_size == 1000:
            current_slice = row[0]
            current_slice_size = 0

        if current_slice not in ip_networks:
            ip_networks[current_slice] = []

        entry = {
            "start": row[0],
            "end": row[1],
            "asn": int(row[2]),
            "country": row[3],
            "name": row[4]
        }

        ip_networks[current_slice].append(entry)
        current_slice_size += 1

    fh.close()

    with gzip.open(cachefile, "wt") as fh:
        print("Persisting cache file for AS parsing {}".format(filename))
        json.dump({"ip_networks": ip_networks}, fh)

    return ip_networks


def get_asn_of_ip(ip: [str, ipaddress.IPv4Address, ipaddress.IPv6Address], ip_networks: dict) -> list:
    if not type(ip) in [ipaddress.IPv4Address, ipaddress.IPv6Address]:
        ip = ipaddress.ip_address(ip)

    candidates = []
    # Iterate over slices to find the right network slice
    match = None
    for slice_start in ip_networks.keys():
        slice_start_ip = ipaddress.ip_address(slice_start)
        if ip == slice_start_ip:
            # we exactly matched the beginning IP of a slice, set it as match
            match = slice_start
            break
        elif ip < slice_start_ip:
            # Searched IP is in previous slice
            break
        # Set slice as possible match, meaning it can be accessed as "previous" slice if the next iteration breaks
        match = slice_start

    if match is None:
        return []

    # Cache processed network conversions
    if match in ipaddressified_ip_networks:
        converted_network = ipaddressified_ip_networks[match]
    else:
        converted_network = ipaddressify_ip_networks(ip_networks[match])
        ipaddressified_ip_networks[match] = converted_network

    # The IP that is searched for is in the last matched slice
    for network in converted_network:
        # Using ipaddress objects as network start and end
        if network["start"] < ip < network["end"] and network["asn"] != 0:
            candidates.append(network)

    return candidates
