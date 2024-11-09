## Notes about functions
- wsman: fastest option, but doesn't detect standard ports such as 21, 25, 110, 143, etc.
- http: most accurate but timeout needs to be set to acceptable value (default 30 seconds, otherwise hangs)
- rest: Similar to http but different function
- mail: slowest option, not as verbose as http but detects ports
- random: makes scan time random, but can miss some ports, likely better to use this option to avoid edr
