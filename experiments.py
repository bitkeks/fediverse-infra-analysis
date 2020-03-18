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

from typing import Dict, Any


def check_multihost(ip_cache: dict, asn_cache: dict) -> Dict[str, Dict[str, Any]]:
    """
    Check which hosters host multiple instances.
    First, iterate through all instances, gather their ASNs and group by ASN.
    Then take each group and examine the IP addresses.
    :param ip_cache:
    :param asn_cache:
    :return:
    """
    asns = {}  # keys are ASNs, values list of hostnames
    asn_to_as: Dict[int, str] = {}
    for instanceName, data in asn_cache.items():
        for network in data["asn"]:
            asn: int = network["asn"]

            if asn not in asn_to_as:
                asn_to_as[asn] = network["name"]

            if asn not in asns:
                asns[asn] = set()

            asns[asn].add(instanceName)

    # Now asns holds the ASN groups
    ip_groups: Dict[str, Dict[str, set]] = {}  # IP address -> [AS, hostnames]
    for asn, instanceNames in asns.items():
        for hostname in instanceNames:
            # IPs are strings

            if hostname not in ip_cache:
                # Sometimes AS and IP caches are out of sync
                continue

            ipv4: [str] = ip_cache.get(hostname)["v4"]
            for ip in ipv4:
                if ip not in ip_groups:
                    ip_groups[ip] = {
                        "as": asn_to_as[asn],
                        "instances": set()
                    }
                ip_groups[ip]["instances"].add(hostname)

            ipv6: [str] = ip_cache.get(hostname)["v6"]
            for ip in ipv6:
                if ip not in ip_groups:
                    ip_groups[ip] = {
                        "as": asn_to_as[asn],
                        "instances": set()
                    }
                ip_groups[ip]["instances"].add(hostname)

    return ip_groups
