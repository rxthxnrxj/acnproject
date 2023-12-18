first.py - listens to the eth0 NIC and collect network logs and append it to the pcap files
>>python3 first.py
second.py -  parses the pcap file updated by first.py and analyses to get details like congestion window, retransmissions, out of order packets, packet loss
>>python3 second.py
realtime.py - does the packet capture and analysis siumultaniously and updates the webpage in realtime to visualize
>>python3 realtime.py
congestion_window_updated.py -  according to the suggestion of the professor during the presentation, we have fixed the logic of congestion window calculation and does the same job as realtime.py
>>pyhton3 congestion_window_updated.py


The code is written, executed and tested in WSL linux (Ubuntu 22.04)