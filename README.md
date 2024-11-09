## Notes about functions
- wsman: fastest option, but least accurate - doesnt detect ports like 135
- http: most accurate but timeout needs to be set to acceptable value (default 30 seconds, otherwise hangs)
- mail: slowest option, not as verbose as http but detects ports
