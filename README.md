# Mastodon infrastructure review 2020

Instances of Mastodon and in the Fediverse are meant to be federated, decentralised platforms. But are they? 

This repo contains the Python tool written for the analysis depicted in the corresponding blog post "[The underlying problem of the Fediverse and other decentralised platforms](https://bitkeks.eu/blog/2020/03/underlying-problem-fediverse-decentralised-platforms.html)" and it's technical counterpart "[Python and data: slicing, caching, threading](https://bitkeks.eu/blog/2020/03/python-data-slicing-caching-threading.html)".

## Usage

To use the program, fetch the data set for Mastodon instances and IP-to-ASN mappings from the [sources](#sources) below and change into the directory where `main.py` is located.

1. Create a virtual env or use `pip install --user` directly and install the requirements: `pip install -r requirements.txt`.
2. Run `python3 main.py` with parameters. Example: `python3 main.py --asn-ipv4 ip2asn-v4.tsv.gz --asn-ipv6 ip2asn-v6.tsv.gz --instances-list instances.json --workers 4 --limit 0 --output results.csv`. Use the flag `-h` to view the help with all CLI parameters.
3. You will see the progress and a lot of output. Configure `main.py` to remove `print` statements you don't need, or insert an `exit(0)` whereever you want (for example not running the experiment).

The **first run might take some minutes** (around six minutes in the test runs, but can be more depending on your network and DNS resolver speed). Subsequent runs will then use the cache files and processing should finish in 4-10 seconds. 
 
**The programm will create multiple files** in the current directory: `.cache_ip`, `.cache_no_ip`, `.cache_asn` and multiple files in the format `.asnfile_cached_<hash>.gz`. 
 
```
usage: main.py [-h] [--asn-ipv4 ASN_IPV4] [--asn-ipv6 ASN_IPV6] [--instances-list INSTANCES_LIST] [--limit INSTANCES_TOP_LIMIT] [--output OUTPUT_FILENAME] [--workers NUM_THREADS]

optional arguments:
  -h, --help            show this help message and exit
  --asn-ipv4 ASN_IPV4
  --asn-ipv6 ASN_IPV6
  --instances-list INSTANCES_LIST
  --limit INSTANCES_TOP_LIMIT
                        Limit of instances to look at, top X instances by users
  --output OUTPUT_FILENAME
                        Name of CSV output file
  --workers NUM_THREADS
                        Amount of workers to use
```

## License
Copyright 2020 Dominik Pataky <dev@bitkeks.eu>

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program.  If not, see <https://www.gnu.org/licenses/>.


## Sources
 * IP to ASN mapping: https://iptoasn.com
 * Mastodon instances data: https://instances.social
 * Paper "Challenges in the Decentralised Web: The Mastodon Case": https://arxiv.org/abs/1909.05801