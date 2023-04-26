# -VUT-ISA2
Network Applications and Administration -  Generation of NetFlow data from captured network traffic

Implement a NetFlow exporter that creates NetFlow records from the captured network data in pcap format and sends to the collector.

### Use:
The program must support the following syntax to run:
- ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]

where
- -f <file> network traffic file name or STDIN,
- -c <neflow_collector:port> IP address or hostname of the NetFlow collector. optionally also UDP port (127.0.0.1:2055, if not specified),
- -a <active_timer> - interval in seconds after which active records are exported to the collector (60 if not specified),
- -i <seconds> - interval in seconds after which inactive records are exported to the collector (10 if not specified),
- -m <count> - flow-cache size. When the max size is reached, the oldest entry in the cache is exported to the collector (1024, if not specified).

All parameters are taken as optional. If any of the parameters is not specified, the default value is used instead.

### Example of use:
- ./flow -f input.pcap -c 192.168.0.1:2055

### Implementation:
- Implement in C/C++, using the libpcap library.
