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

import argparse
import csv
import json
import time
from multiprocessing.pool import ThreadPool
import socket
from collections import namedtuple
from tqdm import tqdm
import os.path

import ip2asn
from graphs import plot_by_instances, plot_by_users, plot_by_active_users
import experiments

NUM_WORKERS = 4
CACHEFILE_NOIP = ".cache_no_ip"
CACHEFILE_IP = ".cache_ip"
CACHEFILE_ASN = ".cache_asn"

HOSTER_MAP = {
    "cloudflarenet": "cloudflare",
    "amazon technologies": "amazon",
    "amazon data services": "amazon",
    "amazon.com, inc.": "amazon",
    "hetzner-": "hetzner",
    "ovh": "ovh",
    "google": "google",
    "digitalocean": "digitalocean",
    "sakura-": "sakura",
    "us-linode-": "linode",
    "linode-": "linode",
    "contabo": "contabo",
    "vultr holdings": "vultr",
    "netcup": "netcup",
    "centurylink communications": "centurylink",
    "comcast cable": "comcast",
    "dreamhost-": "dreamhost",
    "microsoft corporation": "microsoft",
    "gandi-": "gandi",
    "cstnet-": "cstnet",
    "vtcdigicom-": "vtcdigicom",
    "idcf": "idcfrontier",
    "octopuce-": "octopuce",
    "as12876": "scaleway",
    "facebook": "facebook",
    "twitter": "twitter"
}


WorkerResult = namedtuple('WorkerResult', ['hostname', 'v4', 'v6', 'asn'])
CleanupStats = namedtuple('CleanupStats', ['ip', 'no_ip', 'asn'])


def read_instances(filename: str) -> dict:
    with open(filename, "r") as fh:
        return json.load(fh)


def map_whois_to_hoster(item: str) -> [str, None]:
    for hoster in HOSTER_MAP:
        if hoster in item.lower():  # match substrings
            return HOSTER_MAP[hoster]

    # If not found, parse ASN name to find fitting name
    tokens = item.split(" ")
    for token in tokens:
        if token.isupper():  # Find netname which is mostly the upper case string
            new_hoster = token.lower()
            # hoster_map[new_hoster] = new_hoster
            if new_hoster not in hoster_new_created:
                hoster_new_created[new_hoster] = []
            hoster_new_created[new_hoster].append(item)
            return new_hoster

    # If all else fails, return None
    return None


def cleanup_cachefiles() -> CleanupStats:
    """
    Cleans up the cache files based on the entries timeouts
    :return:
    """
    global ip_cache, no_ip_cache, asn_cache
    stats = [0, 0, 0]

    # temporary list of cleanup candidates
    deletion_candidates = []

    # load IP cache
    if os.path.exists(CACHEFILE_IP):
        with open(CACHEFILE_IP, "r") as fh:
            ip_cache = json.load(fh)
    # clean up IP cache
    for hostname in ip_cache:
        if ip_cache[hostname]["timestamp"] < (time.time() - 60 * 60):  # one hour
            # exceeded timeout
            deletion_candidates.append(hostname)
    for can in deletion_candidates:
        del ip_cache[can]

    stats[0] = len(deletion_candidates)
    deletion_candidates.clear()

    # load cache with hosters which could not be resolved in previous runs
    if os.path.exists(CACHEFILE_NOIP):
        with open(CACHEFILE_NOIP, "r") as fh:
            no_ip_cache = json.load(fh)
    for hostname in no_ip_cache:
        if no_ip_cache[hostname] < (time.time() - 60 * 60 * 3):  # three hours
            # timeout limit exceeded, hostname will be tried again
            deletion_candidates.append(hostname)
    for can in deletion_candidates:
        del no_ip_cache[can]

    stats[1] = len(deletion_candidates)
    deletion_candidates.clear()

    # load and clean cache file with ASN mappings
    if os.path.exists(CACHEFILE_ASN):
        with open(CACHEFILE_ASN, "r") as fh:
            asn_cache = json.load(fh)
    for hostname in asn_cache:
        if asn_cache[hostname]["timestamp"] < (time.time() - 60 * 60 * 6):  # six hours
            deletion_candidates.append(hostname)
    for can in deletion_candidates:
        del asn_cache[can]

    stats[2] = len(deletion_candidates)

    return CleanupStats(*stats)


def worker(hostnames: list) -> [WorkerResult]:
    results = []
    for hostname in hostnames:
        v4, v6 = hostname_to_ips(hostname)

        if hostname in asn_cache:
            asn: list = asn_cache[hostname]["asn"]
        else:
            asn = []
            for ip in v4:
                asn += ip2asn.get_asn_of_ip(ip, ip_networks_ipv4)
            for ip in v6:
                asn += ip2asn.get_asn_of_ip(ip, ip_networks_ipv6)

        results.append(WorkerResult(hostname, v4, v6, asn))
    counter.update(len(hostnames))
    return results


def hostname_to_ips(hostname: str) -> tuple:
    if hostname in ip_cache:
        # load IP addresses from cache
        return ip_cache[hostname]["v4"], ip_cache[hostname]["v6"]

    ipv4 = []
    ipv6 = []
    try:
        for s in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP):
            if s[0] == socket.AF_INET:
                ipv4.append(s[4][0])
            if s[0] == socket.AF_INET6:
                ipv6.append(s[4][0])
    except socket.gaierror:
        # [Errno -2] Name or service not known
        pass

    return ipv4, ipv6


if __name__ == "__main__":
    # global variables
    count_total = 0
    count_cf = 0
    count_cf_users = 0
    not_identified = 0
    analysed_instances = {}
    seen_instances = {}
    ip_cache = {}
    skipped_no_ip = []
    no_ip_cache = {}
    asn_cache = {}
    skipped_no_asn = []
    skipped_multiple_asn = []
    skipped_unknown_mapping = []
    counters = {}
    hoster_new_created = {}

    # CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--asn-ipv4', type=str, dest="asn_ipv4")
    parser.add_argument('--asn-ipv6', type=str, dest="asn_ipv6")
    parser.add_argument('--instances-list', type=str, dest="instances_list")
    parser.add_argument("--limit", type=int, dest="instances_top_limit", default=30,
                        help="Limit of instances to look at, top X instances by users")
    parser.add_argument("--output", type=str, dest="output_filename", default="analysis.csv",
                        help="Name of CSV output file")
    parser.add_argument("--workers", type=int, dest="num_threads", default=NUM_WORKERS,
                        help="Amount of workers to use")
    args = parser.parse_args()

    limit = args.instances_top_limit

    ip_networks_ipv4 = None
    ip_networks_ipv6 = None

    if args.asn_ipv4:
        ip_networks_ipv4 = ip2asn.asnfile_init(args.asn_ipv4)
    if args.asn_ipv6:
        ip_networks_ipv6 = ip2asn.asnfile_init(args.asn_ipv6)
    if not ip_networks_ipv4 and not ip_networks_ipv6:
        exit("Use at least one of --ipv4-list or --ipv6-list")

    instances = read_instances(args.instances_list)["instances"]

    cleaned: CleanupStats = cleanup_cachefiles()
    print("Cleanup: {} IPs, {} no-IPs, {} ASNs".format(*cleaned))

    if limit == 0:
        limit = len(instances)

    # Run DNS resolution in multiple threads to bypass long-timed resolutions
    # Run ASN mapping in multiple threads, involving dict lookup and conversion of types to IPAddress
    counter = tqdm(desc="Analysing instances, running worker threads", total=limit, unit="instances")
    pool = ThreadPool(NUM_WORKERS)
    worker_results: [WorkerResult] = []

    # To batch the worker payload, more than one hostname is passed to a worker to be processed.
    # This also helps reducing the overhead for the progress bar, which uses locking for updates
    hostname_batch = []

    for instance in sorted(instances, key=lambda x: int(x["users"]), reverse=True)[:limit]:
        hostname = instance["name"]
        seen_instances[hostname] = instance

        if hostname in no_ip_cache:
            # Skip unresolvable hostnames, if they have failed in previous runs and are within a timeout limit
            skipped_no_ip.append(instance)
            counter.update()
            continue

        if hostname.startswith("you-think-your-fake"):
            # Skip instances with faked statistics
            counter.update()
            continue

        hostname_batch.append(hostname)

        if len(hostname_batch) >= 10:
            # Start full batch
            worker_results.append(pool.apply_async(worker, args=(hostname_batch,)))
            hostname_batch = []  # reset
            continue

    if len(hostname_batch):
        # last items which do not fill a batch
        worker_results.append(pool.apply_async(worker, args=(hostname_batch,)))

    pool.close()
    pool.join()
    counter.close()

    # Re-struct the results, fetching and unpacking each WorkerResult list from the thread result
    worker_results = [] + [item for r in worker_results for item in r.get()]

    # Map ASNs by hostname to a common name, removing duplicates
    bar = tqdm(desc="Analysing instances, mapping ASNs", total=len(worker_results))
    for wr in worker_results:
        hostname = wr.hostname
        instance = seen_instances[hostname]
        bar.update()

        if len(wr.v4) + len(wr.v6) == 0:
            # print(f"No IPs found for instance {hostname}")
            skipped_no_ip.append(instance)  # do this here to avoid problems with threaded access
            no_ip_cache[hostname] = time.time()
            continue

        # Add the IP address resolution to the cache, if entry does not exist
        if hostname not in ip_cache:
            # timeout is handled before, after load from file
            ip_cache[hostname] = {
                "v4": wr.v4,
                "v6": wr.v6,
                "timestamp": time.time()
            }

        # Process ASN, either load from cache or proceed with examination
        if len(wr.asn) == 0:
            # print(f"ASN for {hostname} is of length 0")
            skipped_no_asn.append(instance)
            continue

        # map ASNs to name cluster (merge multiple names for the same provider into one)
        # using set() to remove duplicate network names
        hoster = set([map_whois_to_hoster(item["name"]) for item in wr.asn])

        if len(hoster) > 1:
            # print(f"Instance {hostname} has more than one hosting ASN!")
            # print("{name}:\t{networks}".format(name=hostname, networks=", ".join(hoster)))
            skipped_multiple_asn.append(instance)
            continue

        hoster = hoster.pop()

        if hoster is None:
            skipped_unknown_mapping.append((instance, wr.asn[0]))
            continue

        if hostname not in asn_cache:
            asn_cache[hostname] = {
                "asn": [
                    {"name": asn["name"],
                     "asn": asn["asn"],
                     "country": asn["country"],
                     "start": asn["start"].exploded,
                     "end": asn["end"].exploded
                     } for asn in wr.asn],  # convert IP addresses back to strings for json.dump
                "timestamp": time.time()
            }

        if hoster not in counters:
            counters[hoster] = []
        counters[hoster].append(hostname)

        analysed_instances[hostname] = instance

    bar.close()

    # save caches to persistent files
    with open(CACHEFILE_IP, "w") as fh:
        json.dump(ip_cache, fh)
    with open(CACHEFILE_NOIP, "w") as fh:
        json.dump(no_ip_cache, fh)
    with open(CACHEFILE_ASN, "w") as fh:
        json.dump(asn_cache, fh)

    if skipped_no_ip or skipped_no_asn or skipped_multiple_asn:
        print(f"Skipped instances: {len(skipped_no_ip)} because of no IP (including cached), "
              f"{len(skipped_no_asn)} because no ASN were found and "
              f"{len(skipped_multiple_asn)} because multiple ASNs were found")

    if skipped_unknown_mapping:
        for instance, asn in skipped_unknown_mapping:
            print(f"Instance {instance['name']} skipped because ASN '{asn['name']}' could not be mapped")

    for new_hoster, asns in hoster_new_created.items():
        if len(asns) > 1:
            print(f"New hoster {new_hoster} created by multiple ASNs: {set(asns)} (total {len(asns)})")

    x, y1, y2 = [], [], []

    # Providers with 6-20 instances
    medium_hosters_instances, medium_hosters_users = 0, 0
    # Providers with 2-5 instances
    small_hosters_instances, small_hosters_users = 0, 0
    # At some point hosters will appear which only host one single instance. Merge them into one provider
    single_hosters_instances, single_hoster_users = 0, 0

    for hoster, hosted_instances in sorted(counters.items(), key=lambda x: len(x[1]), reverse=True):
        hosted_users = 0
        for instance in hosted_instances:
            hosted_users += int(analysed_instances[instance]["users"])

        percent_instances = round(len(hosted_instances) / len(analysed_instances) * 100, 2)

        hi = len(hosted_instances)

        if hi == 1:
            # Add values to cumulated "others" provider
            single_hosters_instances += 1
            single_hoster_users += hosted_users
            continue

        if hi <= 9:
            small_hosters_instances += hi
            small_hosters_users += hosted_users
            continue

        if hi <= 18:
            medium_hosters_instances += hi
            medium_hosters_users += hosted_users
            continue

        # Hosters with >20 instances
        x.append(f"{hoster} ({percent_instances}%)")
        y1.append(len(hosted_instances))
        y2.append(hosted_users)

    # Append medium hosters
    x.append("(10-18)")
    y1.append(medium_hosters_instances)
    y2.append(medium_hosters_users)

    # Append small hosters as single hoster
    x.append("(2-9)")
    y1.append(small_hosters_instances)
    y2.append(small_hosters_users)

    # At the end, add the "others" provider with the sum of hosted users
    x.append("(1)")
    y1.append(single_hosters_instances)
    y2.append(single_hoster_users)

    # print(x, y1, y2)
    plot_by_instances(x, y1, y2)

    # Iterate again, this time sorting by users
    # We cannot re-use the data above, since the aggregation of multiple providers into groups (single, small,
    # medium) might hide big instances, which we would like to examine in this next step.

    for user_category in ["users", "active_users"]:
        hosters = {}

        # use if/else because dead instances don't have a value for active_users
        total_users_fediverse = sum([int(insta[user_category] if insta[user_category] else 0)
                                     for insta in analysed_instances.values()])

        for hoster, hosted_instances in sorted(counters.items(), key=lambda x: len(x[1]), reverse=True):
            hosted_users = sum([int(analysed_instances[instance][user_category])  # amount
                                if analysed_instances[instance][user_category] else 0  # if not None
                                for instance in hosted_instances])  # for each instance at this provider

            percent_users = round(hosted_users / total_users_fediverse * 100, 2)

            hosters[f"{hoster} ({percent_users}%)"] = {
                "users": hosted_users,
                "instances": len(hosted_instances)
            }

        x, y1, y2 = [], [], []  # reset

        others = 0
        others_users = 0
        others_instances = 0

        total_users = 0
        total_instances = 0

        for hoster, data in sorted(hosters.items(), key=lambda x: x[1]["users"], reverse=True):
            hosted_users = data["users"]
            hosted_instances = data["instances"]

            total_users += hosted_users
            total_instances += hosted_instances

            if len(x) >= 20:
                others += 1
                others_users += hosted_users
                others_instances += hosted_instances
                continue

            x.append(hoster)
            y1.append(hosted_users)
            y2.append(hosted_instances)

        x.append("Others ({})".format(others))
        y1.append(others_users)
        y2.append(others_instances)
        plot_by_users(x, y1, y2) if user_category == "users" else plot_by_active_users(x, y1, y2)

    # Markdown export hack
    print("\n\nMarkdown export\n\n| Hoster | Users | U% | Instances | I% |")
    print("|" + "---|" * 5)
    lines = 0
    for hoster, data in sorted(hosters.items(), key=lambda x: x[1]["users"], reverse=True):
        if lines > 20:
            break
        hosted_users = data["users"]
        hosted_instances = data["instances"]

        print("| {hoster} | {users} | {users_p}% | {instances} | {instances_p}% |".format(
            hoster=hoster,
            users=hosted_users, users_p=round(hosted_users/total_users*100, 2),
            instances=hosted_instances, instances_p=round(hosted_instances/total_instances*100, 2)
        ))
        lines += 1

    print(f"\n\nWriting CSV file to {args.output_filename}")
    with open(args.output_filename, "w") as fh:
        csvwriter = csv.writer(fh, delimiter=',')
        csvwriter.writerow(["instance",
                            "users", "active_users",
                            "statuses", "connections",
                            "ipv6", "hoster",
                            "hosted_instances", "percent_instances",
                            "hosted_users", "percent_users"])

        for hoster, hostnames in sorted(counters.items(), key=lambda x: len(x[1]), reverse=True):
            hosted_users = 0
            for hostname in hostnames:
                hosted_users += int(analysed_instances[hostname]["users"])

            percent_users = round(hosted_users / total_users * 100, 3)
            percent_instances = round(len(hostnames) / len(analysed_instances) * 100, 3)
            # print(hoster, len(hostnames), round(len(hostnames) / len(analysed_instances) * 100, 3),
            #       hosted_users, percent_users)
            for hostname in hostnames:
                csvwriter.writerow([
                    hostname,
                    analysed_instances[hostname]["users"], analysed_instances[hostname]["active_users"],
                    analysed_instances[hostname]["statuses"], analysed_instances[hostname]["connections"],
                    analysed_instances[hostname]["ipv6"], hoster,
                    len(hostnames), percent_instances,
                    hosted_users, percent_users])

    # experiment 1: check IPs which host more than 10 instances
    ip_groups = experiments.check_multihost(ip_cache, asn_cache)
    for ip, data in sorted(ip_groups.items(), key=lambda x: len(x[1]["instances"]), reverse=True)[:5]:
        hoster = data["as"]
        hostnames = data["instances"]
        if len(hostnames) > 10:
            print(f"\nIP {ip} ({hoster}) hosts {len(hostnames)} instances: {hostnames}")
