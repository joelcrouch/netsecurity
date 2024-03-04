### Find The Firmware
    
## Introduction
This homework was pretty challenging. These are the parameters and requirements. The packet capture is at ada.cs.pdx.edu:/disk/scratch/dmcgrath/firmware.pcap. Simply scp it to your VM. It is important to note that HTTP often transmits binary data via BASE64 encoding!  Don't forget this part.
This is directly from the assignment.
Some useful information regarding the firmware you’re after:

┌─(dmcgrath@kali:pts/3)─────────────────────────────────────────────────────────────────────────(~)─┐
└─(14:43:%)── binwalk download.bin #what it should look like                          ──(Wed,Sep23)─┘

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
48            0x30            Unix path: /dev/mtdblock/2
96            0x60            LZMA compressed data, properties: 0x6D, dictionary size: 8388608 bytes, uncompressed size: 4438276 bytes
302958        0x49F6E         MySQL MISAM index file Version 4
1441888       0x160060        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2208988 bytes, 1159 inodes, blocksize: 262144 bytes, created: 2019-08-06 21:20:37

┌─(dmcgrath@kali:pts/3)─────────────────────────────────────────────────────────────────────────(~)─┐
└─(14:43:%)── md5sum download.bin                                                     ──(Wed,Sep23)─┘
7aa6a7ebcbd98ce19539b668ff790655  download.bin
┌─(dmcgrath@kali:pts/3)─────────────────────────────────────────────────────────────────────────(~)─┐
└─(14:44:%)── sha512sum download.bin                                                  ──(Wed,Sep23)─┘
2a7719719aa4f869586a7043f532e01ed4985e5c25b9a54979ac7d50c67820ec61c2805d6169b9c95a98104b8fb1d4f9ec698d23881360e99f5232a4f3cf12d4  download.bin
┌─(dmcgrath@kali:pts/3)─────────────────────────────────────────────────────────────────────────(~)─┐
└─(14:44:%)──                                                                         ──(Wed,Sep23)─┘

Once you have a firmware extracted that matches the above, use a tool called binwalk to extract the contents (this isn’t a reverse engineering class, use the -M and -e options), then answer a few questions:

    What architecture is the firmware intended to run on?
    What OS is the firmware running?
    What users are present on the system?
## Trials and Tribulations

So I have the capture on my Kali VM or locally, and it is open in wireshark. There are 237000 odd some packets to look at so, just trying to do it manually is out of the question.  I looked at the output of wireshark, and noticed what I think might be the target: 'firmware.bin' is in a bunch of packets. This is one of the important lines from wireshark:
``` wireshark
28490	14:39:32.899	192.168.86.167	192.168.86.228	HTTP	233	GET /download?name=firmware.bin&offset=0&size=1024 HTTP/1.1 

```

Ok, great. That looks promising. Now i can look inside that packet and see if there are any similarities amongst the GET requests.  There certainly are. In the HTTP portion, this line exists: 
``` wireshark 
Host: 192.168.86.228:5000\r\n
```
That tells me (eventually) the server IP address and port numbers are 192.168.86.228 and 5000 respectively.  So, now I can apply a new filter to to 'firmware.pcap':  'tcp.port==5000 && ip.addr == 192.168.86.228 '  That narrows down the number of packets a little bit.  Now look at the output from Wireshark.  It looks generally the same, so take another look this line:
``` wireshark
28490	14:39:32.899	192.168.86.167	192.168.86.228	HTTP	233	GET /download?name=firmware.bin&offset=0&size=1024 HTTP/1.1 

28514	14:39:32.978	192.168.86.167	192.168.86.228	HTTP	236	GET /download?name=firmware.bin&offset=2048&size=1024 HTTP/1.1 

28526	14:39:33.083	192.168.86.167	192.168.86.228	HTTP	236	GET /download?name=firmware.bin&offset=3072&size=1024 HTTP/1.1 
```
Looking at these 3 GETs, i can see there are generally the same. 
(number time ip.src ip.dst Protoco response-code Method path)  Within the path we can see an 'offset' and 'size'.  They might be useful.  Here is where i went into a deep rabbit-hole and kept on digging.  I want to extract the offset number, and if it exists, the TCP payload, because I think that is the binary that i want to put back together.  So i want to create a linked list with offset in one data field and the data from the payload in the other data field.  That way i can put the data back together in the right order. Sounds great!  So i tried to do this:
``` 
python

from scapy.all import rdpcap, IP, TCP
import os

class DataNode:
  def __init__(self, offset, data):
    self.offset = offset
    self.data = data

def process_pcap(filename):
  packets = rdpcap(filename)

  data_list = []  # Using a list for sorting

  for packet in packets:
    if packet.haslayer("HTTP"):
        # Check for specific Request URI and data field
        if "[Request URI: http://192.168.86.228:5000/download?name=firmware.bin&offset=" in packet[HTTP].Request_URI and packet.haslayer("Raw"):
          # Extract offset and data
          offset = int(packet[HTTP].Request_URI.split("=")[2])
          data = packet[Raw].load.decode("base64")
          new_node = DataNode(offset, data)

          # Insert and sort using list comprehension
          data_list = [node for node in sorted((data_list + [new_node]), key=lambda n: n.offset)]

  # Write data to a file in order
  with open("download.bin", "wb") as f:
    for node in data_list:
      f.write(node.data)

  # Analyze the reassembled file
  os.system(f"binwalk download.bin")
```

Here i have created a linked list, with the appropriate fields, and then iterate through all the packets.  This did not work at all.  I got a bunch of garbage. 
``` bash

binwalk -M -e download.bin                                                                              

Scan Time:     2024-02-25 00:24:31
Target File:   /home/joel/download.bin
MD5 Checksum:  85dabfc01ccf069b8b30984100bfaad9
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


```

I think that oughtta work, so i bashed around with it. I tried doing similar things using the scapy prompt, and after much bashing around, it became clear to me that 'httprequest' was not working, nor was any of the 'http' functions included in scapy on this particular piece of data.  What on earth could be going on? Per Kevin's warnings, I recalled "WIRESHARK will lie to you like that was its job!"  
Maybe there is another way to extract the offset.  Turns out the offset is also included in the first 'Raw' load.  So now i can just extract that and get the data and match it up.  
Here's a big 'but'.  The data is not sent over in one packet, and wireshark lies about rebuilding it into one packet. So load that file into scapy and you can see that the data comes in a pattern:  1 :get with offset, 2  data 3 data.  Three different packets with the data i need to make this a working binary.  The pattern can be seen here after: p=rdpcap('filter.pcap') where filter is the filter mentioned above and the file saved as 'filter.pcap'.  
``` 
scapy 
p.summary()
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37266 SA
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37266 A
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37266 PA / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37266 A / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37266 FPA / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37266 A
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37268 SA
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37268 A
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37268 PA / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37268 A / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37268 FPA / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37268 A
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37270 SA
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37270 A
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37270 PA / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37270 A / Raw
Ether / IP / TCP 192.168.86.228:5000 > 192.168.86.167:37270 FPA / Raw

```
In this file we have get, data, data, followed by 3 inconsequential packets (A, SA, A).  See lines 114-119.  So now we have something. Lets assume all the packets came in order, such that i can just grab the Raw load from each triplet, decode it, and add it to a binary(download.bin).  It would be something like this:
```
psuedo-python
for i in p:
    if there is a Raw field and if the Raw field starts with GET    
            extract the Raw data
            write it to a file
            i+1
            extract the Raw data
            write it to a file
            i+=1
            extract the Raw data
            write it to a file
            i+3
    i+=1
```
Explanation:  For each packet, check to see if there is a Raw field and if it starts with GET. That way you know its the first packet in the three packet trio. Then get that data, strip out the extra stuff, grab the encoded base64 data, decode it write it to a binary. Then do the same type of extraction to the next two packets.  Add 3 to skip the inconsequential packets, or if there wasn't a Raw field or it didnt start with Get, then iterate to the next packet.  Easy-cheesy.  Sure.
This was one of my first naive attempts to get the raw data without and parsing or logic regarding the 1,2,3, +3 pattern of packets. 

```python 
from scapy.all import rdpcap, TCP, IP
import base64

def concat_binary(pcap_filename, output_filename):
    p=rdpcap(pcap_filename)
    with open(output_filename, 'wb') as output_file:
        for packet in p:
            if 'TCP' in packet and 'Raw' in packet: 
                tcp_payload=p['Raw'].load.decode('utf-8', 'ignore')
                btcp_payload=base64.b64decode(tcp_payload)
                output_file.write(btcp_payload)
if __name__ == "__main__":
    pcap_filename="filter.pcap"
    output_filename="concat_output.bin"
    concat_binary(pcap_filename, output_filename)
```

So that output was trash:
```bash
binwalk -M -e concatenated_output.bin

Scan Time:     2024-02-25 01:06:02
Target File:   /home/joel/concatenated_output.bin
MD5 Checksum:  85dabfc01ccf069b8b30984100bfaad9
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

```
It did some stuff, but not of any consequence but I can get the Raw data out!  Huzzah.  Now i went down another long rabbit hole, attempting to get the offset from the http portion of the packet. After way too much 'scapy-http' wrangling, i did this, and just visually inspected the packets that were currently in my file in scapy:
```
scapy

>> for i in range(1, 15):
...:     p[i].show()
...: 
###[ Ethernet ]### 
  dst       = 1c:87:2c:b6:58:73
  src       = b8:8a:60:a7:06:f2
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
...
```

I looked at these packets, and I can see the packets of interest, but no HTTP layer is listed. So there is no way that http access to get the offset and size would work. Sugar-shorts.  Ok.  Back to the drawing board.  Lets look at the packets again.

## Solution Part 1
After bashing around for way too long, office hours and class time was enlightening.  Instead of using a logical method to extract the 3rd, 7th and 9th packets where the raw file resides, one can just do this:
```
python + bash
packets=sniff(offline="firmware.pcap, filter="host 192.168.86.228 and host 192.168.86.167")
less=packets[Raw]
```
The first line 'sniffs' firmware.pcap and filters it on the two IP addresses.  Then and this is the crux of the whole matter, the second just gets the packets that have a Raw payload. Now we can just iterate through the loop and get the data. We are assuming everything is in order.

Final loop:
```
scapy
>>> for i in range(0,len(less),4):
...:     if i+2< len(less) and i+3 < len(less):
...:         first=less[i+2][Raw].load
...:         second=less[i+3][Raw].load
...:         if b'\r\n\r\n' in first:
...:             index=first.find(b'\r\n\r\n') +4
...:             b=base64_bytes(first[index:]+second)
...:             a=f.write(b)
...: 
>>> 

```

## Result Binwalk
Here are the results of binwalk:
```
bash

(joel㉿LAPTOP-M41GA6ID)-[~]
└─$ binwalk -M -e download.bin                                                                                                                           

Scan Time:     2024-03-02 08:51:52
Target File:   /home/joel/download.bin
MD5 Checksum:  7ad374c21460ebeb5092f5c399f0abad
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
48            0x30            Unix path: /dev/mtdblock/2
96            0x60            LZMA compressed data, properties: 0x6D, dictionary size: 8388608 bytes, uncompressed size: 4438276 bytes
302958        0x49F6E         MySQL MISAM index file Version 4

```

That is kind of correct, but the squashfs file system is missing.  Again-Sugar-shorts. That implies some of the data is out of order/missing.  Lets continue and see if i can get the answers required.

## Interrogating the binary






