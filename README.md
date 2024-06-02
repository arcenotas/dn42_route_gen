# DN42 Route Gen
This is a simple program that takes [DN42](https://dn42.dev/Home) registry data and computes corrensponding ROA data for [StayRTR](https://github.com/bgp/stayrtr).

Usage:
```
$ git clone https://github.com/arcenotas/dn42_route_gen.git
$ cd dn42_route_gen
$ cargo build --release
$ ./target/release/dn42_route_gen <registry_directory> <output_file>
```

You can then use a webserver of your choice to serve the output file to StayRTR.

It is recommended to run this program as a cron job to keep the output file up to date. Don't forget to `git pull` before running the program!

This program is currently supporting AS4242420625.
