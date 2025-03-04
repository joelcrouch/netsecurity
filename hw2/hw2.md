# NETSEC

## Description
Get comfortable with capturing network traffic using tcpdump, and maybe wireshark and tshark.  The tcpdump will be running on a WSL instance of Kali linux. 

### Tasks
These are the tasks that will be done to show some knowledge of tcpdump.  This is primarily gained from reading the man pages.  

    1.Perform a tcpdump capture where you only capture DNS packets.
    2.Perform a tcpdump capture where you capture TCP packets that are destined      for either port 443 or 8080, and originate from your computer.
    3. Perform a tcpdump capture where traffic is either UDP or TCP, is inbound to your computer, and destined for a port between 20000 and 35000.

## Results

### Issue #1 
The first issue i ran into and had to solve was the Kali VM uses up all the screen space, and there is not a 'minimize' button.  Opening up the gui with 'kex --win -s' should open up a windowed instance of Kali.  Digging deeper into the documentation yielded the following solution:  'fn + f8' opens a dialogue that allows for minimization of the window. Alternatively, you could just access the internet from inside the Kali instance.  Most of the information that is required is there.  This allows for using both windows and Kali linux somewhat simultaneously.  

### Task 1: Perform a tcpdump capture where you only capture DNS packets.  Eventually i got to this command:
``` zsh
sudo tcpdump -i any -n -tttt -xx -X -c 30 port 53 >dnsdump.txt

``` 
Explanation of the flags: 
    -sudo tcpdump: Use sudo to execute the command with root powers.
    -i any: Specifies the network interface to capture packets from. In this case, any is used to capture from all available interfaces.  Other interfaces can be acquired by running 'ifpconfig', or 'iwconfig' or 'ip a s'.  (windows, Mac, Linux,respectively, maybe)
    -n: Disables the DNS resolution for IP addresses and port numbers. Displays numerical values instead of resolving them to hostnames or service names.
    -tttt: Displays timestamps in Unix epoch format for each packet.
    -xx: Prints the hexadecimal and ASCII representation of the packet data.
    -X: Displays  the info for each packet in both hex and ASCII formats.
    -c 30:  'Count'-just get 30 packets.
    -port 53: Filters packets to capture only those that are destined for port 53 (DNS).  I knew this was the DNS port from class.  There might be a command that allows one to see the ports, but you can just look here-wikipedia well known ports: https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers.
    >dnsdump.txt  I used this for ease of copy/pasting, essentially. 
    
    The following is the result of the command above.
    ``` 
    024-02-12 21:22:44.993196 eth0  Out IP 172.25.5.220.57287 > LAPTOP-M41GA6ID.domain: 58776+ A? github.com. (28)
	0x0000:  4500 0038 c4a1 4000 4011 1804 ac19 05dc  E..8..@.@.......
	0x0010:  ac19 0001 dfc7 0035 0024 5e45 e598 0100  .......5.$^E....
	0x0020:  0001 0000 0000 0000 0667 6974 6875 6203  .........github.
	0x0030:  636f 6d00 0001 0001                      com.....
2024-02-12 21:22:45.054246 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.57287: 58776- 1/0/0 A 192.30.255.113 (54)
	0x0000:  4500 0052 39de 0000 8011 a2ad ac19 0001  E..R9...........
	0x0010:  ac19 05dc 0035 dfc7 003e 85a9 e598 8100  .....5...>......
	0x0020:  0001 0001 0000 0000 0667 6974 6875 6203  .........github.
	0x0030:  636f 6d00 0001 0001 0667 6974 6875 6203  com......github.
	0x0040:  636f 6d00 0001 0001 0000 0000 0004 c01e  com.............
	0x0050:  ff71                                     .q
2024-02-12 21:22:45.388370 eth0  Out IP 172.25.5.220.56623 > LAPTOP-M41GA6ID.domain: 51117+ PTR? 1.0.25.172.in-addr.arpa. (41)
	0x0000:  4500 0045 f08d 4000 4011 ec0a ac19 05dc  E..E..@.@.......
	0x0010:  ac19 0001 dd2f 0035 0031 5e52 c7ad 0100  ...../.5.1^R....
	0x0020:  0001 0000 0000 0000 0131 0130 0232 3503  .........1.0.25.
	0x0030:  3137 3207 696e 2d61 6464 7204 6172 7061  172.in-addr.arpa
	0x0040:  0000 0c00 01                             .....
2024-02-12 21:22:46.156333 eth0  Out IP 172.25.5.220.55665 > LAPTOP-M41GA6ID.domain: 20344+ A? collector.github.com. (38)
	0x0000:  4500 0042 d220 4000 4011 0a7b ac19 05dc  E..B..@.@..{....
	0x0010:  ac19 0001 d971 0035 002e 5e4f 4f78 0100  .....q.5..^OOx..
	0x0020:  0001 0000 0000 0000 0963 6f6c 6c65 6374  .........collect
	0x0030:  6f72 0667 6974 6875 6203 636f 6d00 0001  or.github.com...
	0x0040:  0001                                     ..
2024-02-12 21:22:46.181500 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.55665: 20344- 2/0/0 CNAME glb-db52c2cf8be544.github.com., A 140.82.112.22 (146)
	0x0000:  4500 00ae 39df 0000 8011 a250 ac19 0001  E...9......P....
	0x0010:  ac19 05dc 0035 d971 009a 04c3 4f78 8100  .....5.q....Ox..
	0x0020:  0001 0002 0000 0000 0963 6f6c 6c65 6374  .........collect
	0x0030:  6f72 0667 6974 6875 6203 636f 6d00 0001  or.github.com...
	0x0040:  0001 0963 6f6c 6c65 6374 6f72 0667 6974  ...collector.git
	0x0050:  6875 6203 636f 6d00 0005 0001 0000 0000  hub.com.........
	0x0060:  001f 1267 6c62 2d64 6235 3263 3263 6638  ...glb-db52c2cf8
	0x0070:  6265 3534 3406 6769 7468 7562 0363 6f6d  be544.github.com
	0x0080:  0012 676c 622d 6462 3532 6332 6366 3862  ..glb-db52c2cf8b
	0x0090:  6535 3434 0667 6974 6875 6203 636f 6d00  e544.github.com.
	0x00a0:  0001 0001 0000 0000 0004 8c52 7016       ...........Rp.
2024-02-12 21:22:46.415521 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.56623: 51117- 1/0/0 PTR LAPTOP-M41GA6ID. (93)
	0x0000:  4500 0079 39e0 0000 8011 a284 ac19 0001  E..y9...........
	0x0010:  ac19 05dc 0035 dd2f 0065 b315 c7ad 8100  .....5./.e......
	0x0020:  0001 0001 0000 0000 0131 0130 0232 3503  .........1.0.25.
	0x0030:  3137 3207 696e 2d61 6464 7204 6172 7061  172.in-addr.arpa
	0x0040:  0000 0c00 0101 3101 3002 3235 0331 3732  ......1.0.25.172
	0x0050:  0769 6e2d 6164 6472 0461 7270 6100 000c  .in-addr.arpa...
	0x0060:  0001 0000 0000 0011 0f4c 4150 544f 502d  .........LAPTOP-
	0x0070:  4d34 3147 4136 4944 00                   M41GA6ID.
2024-02-12 21:22:46.415696 eth0  Out IP 172.25.5.220.46410 > LAPTOP-M41GA6ID.domain: 40627+ PTR? 220.5.25.172.in-addr.arpa. (43)
	0x0000:  4500 0047 3969 4000 4011 a32d ac19 05dc  E..G9i@.@..-....
	0x0010:  ac19 0001 b54a 0035 0033 5e54 9eb3 0100  .....J.5.3^T....
	0x0020:  0001 0000 0000 0000 0332 3230 0135 0232  .........220.5.2
	0x0030:  3503 3137 3207 696e 2d61 6464 7204 6172  5.172.in-addr.ar
	0x0040:  7061 0000 0c00 01                        pa.....
2024-02-12 21:22:46.540855 eth0  Out IP 172.25.5.220.48841 > LAPTOP-M41GA6ID.domain: 34473+ A? api.github.com. (32)
	0x0000:  4500 003c dc4e 4000 4011 0053 ac19 05dc  E..<.N@.@..S....
	0x0010:  ac19 0001 bec9 0035 0028 5e49 86a9 0100  .......5.(^I....
	0x0020:  0001 0000 0000 0000 0361 7069 0667 6974  .........api.git
	0x0030:  6875 6203 636f 6d00 0001 0001            hub.com.....
2024-02-12 21:22:46.552292 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.48841: 34473- 1/0/0 A 192.30.255.116 (62)
	0x0000:  4500 005a 39e1 0000 8011 a2a2 ac19 0001  E..Z9...........
	0x0010:  ac19 05dc 0035 bec9 0046 1def 86a9 8100  .....5...F......
	0x0020:  0001 0001 0000 0000 0361 7069 0667 6974  .........api.git
	0x0030:  6875 6203 636f 6d00 0001 0001 0361 7069  hub.com......api
	0x0040:  0667 6974 6875 6203 636f 6d00 0001 0001  .github.com.....
	0x0050:  0000 0000 0004 c01e ff74                 .........t
2024-02-12 21:22:47.466816 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.46410: 40627 NXDomain 0/0/0 (43)
	0x0000:  4500 0047 39e2 0000 8011 a2b4 ac19 0001  E..G9...........
	0x0010:  ac19 05dc 0035 b54a 0033 aea9 9eb3 8183  .....5.J.3......
	0x0020:  0001 0000 0000 0000 0332 3230 0135 0232  .........220.5.2
	0x0030:  3503 3137 3207 696e 2d61 6464 7204 6172  5.172.in-addr.ar
	0x0040:  7061 0000 0c00 01                        pa.....
2024-02-12 21:22:47.582062 eth0  Out IP 172.25.5.220.53122 > LAPTOP-M41GA6ID.domain: 20156+ A? www.kali.org. (30)
	0x0000:  4500 003a 0198 4000 4011 db0b ac19 05dc  E..:..@.@.......
	0x0010:  ac19 0001 cf82 0035 0026 5e47 4ebc 0100  .......5.&^GN...
	0x0020:  0001 0000 0000 0000 0377 7777 046b 616c  .........www.kal
	0x0030:  6903 6f72 6700 0001 0001                 i.org.....
2024-02-12 21:22:47.582205 eth0  Out IP 172.25.5.220.36137 > LAPTOP-M41GA6ID.domain: 21537+ A? fonts.gstatic.com. (35)
	0x0000:  4500 003f 3c58 4000 4011 a046 ac19 05dc  E..?<X@.@..F....
	0x0010:  ac19 0001 8d29 0035 002b 5e4c 5421 0100  .....).5.+^LT!..
	0x0020:  0001 0000 0000 0000 0566 6f6e 7473 0767  .........fonts.g
	0x0030:  7374 6174 6963 0363 6f6d 0000 0100 01    static.com.....
2024-02-12 21:22:47.583429 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.36137: 21537- 1/0/0 A 142.251.33.99 (68)
	0x0000:  4500 0060 39e3 0000 8011 a29a ac19 0001  E..`9...........
	0x0010:  ac19 05dc 0035 8d29 004c 1ef2 5421 8100  .....5.).L..T!..
	0x0020:  0001 0001 0000 0000 0566 6f6e 7473 0767  .........fonts.g
	0x0030:  7374 6174 6963 0363 6f6d 0000 0100 0105  static.com......
	0x0040:  666f 6e74 7307 6773 7461 7469 6303 636f  fonts.gstatic.co
	0x0050:  6d00 0001 0001 0000 0000 0004 8efb 2163  m.............!c
2024-02-12 21:22:47.583440 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.53122: 20156- 2/0/0 A 104.18.4.159, A 104.18.5.159 (74)
	0x0000:  4500 0066 39e4 0000 8011 a293 ac19 0001  E..f9...........
	0x0010:  ac19 05dc 0035 cf82 0052 26bb 4ebc 8100  .....5...R&.N...
	0x0020:  0001 0002 0000 0000 0377 7777 046b 616c  .........www.kal
	0x0030:  6903 6f72 6700 0001 0001 0377 7777 046b  i.org......www.k
	0x0040:  616c 6903 6f72 6700 0001 0001 0000 0000  ali.org.........
	0x0050:  0004 6812 049f c01e 0001 0001 0000 0000  ..h.............
	0x0060:  0004 6812 059f                           ..h...
2024-02-12 21:22:48.152451 eth0  Out IP 172.25.5.220.36145 > LAPTOP-M41GA6ID.domain: 43739+ A? fonts.gstatic.com. (35)
	0x0000:  4500 003f 7ce0 4000 4011 5fbe ac19 05dc  E..?|.@.@._.....
	0x0010:  ac19 0001 8d31 0035 002b 5e4c aadb 0100  .....1.5.+^L....
	0x0020:  0001 0000 0000 0000 0566 6f6e 7473 0767  .........fonts.g
	0x0030:  7374 6174 6963 0363 6f6d 0000 0100 01    static.com.....
2024-02-12 21:22:48.153476 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.36145: 43739- 1/0/0 A 142.251.33.99 (68)
	0x0000:  4500 0060 39e5 0000 8011 a298 ac19 0001  E..`9...........
	0x0010:  ac19 05dc 0035 8d31 004c c82f aadb 8100  .....5.1.L./....
	0x0020:  0001 0001 0000 0000 0566 6f6e 7473 0767  .........fonts.g
	0x0030:  7374 6174 6963 0363 6f6d 0000 0100 0105  static.com......
	0x0040:  666f 6e74 7307 6773 7461 7469 6303 636f  fonts.gstatic.co
	0x0050:  6d00 0001 0001 0000 0000 0004 8efb 2163  m.............!c
2024-02-12 21:22:48.763753 eth0  Out IP 172.25.5.220.33874 > LAPTOP-M41GA6ID.domain: 48847+ A? chat.openai.com. (33)
	0x0000:  4500 003d dc8b 4000 4011 0015 ac19 05dc  E..=..@.@.......
	0x0010:  ac19 0001 8452 0035 0029 5e4a becf 0100  .....R.5.)^J....
	0x0020:  0001 0000 0000 0000 0463 6861 7406 6f70  .........chat.op
	0x0030:  656e 6169 0363 6f6d 0000 0100 01         enai.com.....
2024-02-12 21:22:48.763760 eth0  Out IP 172.25.5.220.33874 > LAPTOP-M41GA6ID.domain: 53963+ AAAA? chat.openai.com. (33)
	0x0000:  4500 003d dc8c 4000 4011 0014 ac19 05dc  E..=..@.@.......
	0x0010:  ac19 0001 8452 0035 0029 5e4a d2cb 0100  .....R.5.)^J....
	0x0020:  0001 0000 0000 0000 0463 6861 7406 6f70  .........chat.op
	0x0030:  656e 6169 0363 6f6d 0000 1c00 01         enai.com.....
2024-02-12 21:22:48.764835 eth0  Out IP 172.25.5.220.50585 > LAPTOP-M41GA6ID.domain: 64837+ A? events.statsigapi.net. (39)
	0x0000:  4500 0043 780d 4000 4011 648d ac19 05dc  E..Cx.@.@.d.....
	0x0010:  ac19 0001 c599 0035 002f 5e50 fd45 0100  .......5./^P.E..
	0x0020:  0001 0000 0000 0000 0665 7665 6e74 730a  .........events.
	0x0030:  7374 6174 7369 6761 7069 036e 6574 0000  statsigapi.net..
	0x0040:  0100 01                                  ...
2024-02-12 21:22:48.764841 eth0  Out IP 172.25.5.220.50585 > LAPTOP-M41GA6ID.domain: 32065+ AAAA? events.statsigapi.net. (39)
	0x0000:  4500 0043 780e 4000 4011 648c ac19 05dc  E..Cx.@.@.d.....
	0x0010:  ac19 0001 c599 0035 002f 5e50 7d41 0100  .......5./^P}A..
	0x0020:  0001 0000 0000 0000 0665 7665 6e74 730a  .........events.
	0x0030:  7374 6174 7369 6761 7069 036e 6574 0000  statsigapi.net..
	0x0040:  1c00 01                                  ...
2024-02-12 21:22:48.784176 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.50585: 64837- 1/0/0 A 34.120.214.181 (76)
	0x0000:  4500 0068 39e6 0000 8011 a28f ac19 0001  E..h9...........
	0x0010:  ac19 05dc 0035 c599 0054 31bb fd45 8100  .....5...T1..E..
	0x0020:  0001 0001 0000 0000 0665 7665 6e74 730a  .........events.
	0x0030:  7374 6174 7369 6761 7069 036e 6574 0000  statsigapi.net..
	0x0040:  0100 0106 6576 656e 7473 0a73 7461 7473  ....events.stats
	0x0050:  6967 6170 6903 6e65 7400 0001 0001 0000  igapi.net.......
	0x0060:  0000 0004 2278 d6b5                      ...."x..
2024-02-12 21:22:48.784290 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.33874: 53963- 3/0/0 CNAME chat.openai.com.cdn.cloudflare.net., AAAA 2606:4700:4400::ac40:961c, AAAA 2606:4700:4400::6812:25e4 (186)
	0x0000:  4500 00d6 39e7 0000 8011 a220 ac19 0001  E...9...........
	0x0010:  ac19 05dc 0035 8452 00c2 6fe7 d2cb 8100  .....5.R..o.....
	0x0020:  0001 0003 0000 0000 0463 6861 7406 6f70  .........chat.op
	0x0030:  656e 6169 0363 6f6d 0000 1c00 0104 6368  enai.com......ch
	0x0040:  6174 066f 7065 6e61 6903 636f 6d00 0005  at.openai.com...
	0x0050:  0001 0000 0000 0024 0463 6861 7406 6f70  .......$.chat.op
	0x0060:  656e 6169 0363 6f6d 0363 646e 0a63 6c6f  enai.com.cdn.clo
	0x0070:  7564 666c 6172 6503 6e65 7400 0463 6861  udflare.net..cha
	0x0080:  7406 6f70 656e 6169 0363 6f6d 0363 646e  t.openai.com.cdn
	0x0090:  0a63 6c6f 7564 666c 6172 6503 6e65 7400  .cloudflare.net.
	0x00a0:  001c 0001 0000 0000 0010 2606 4700 4400  ..........&.G.D.
	0x00b0:  0000 0000 0000 ac40 961c c060 001c 0001  .......@...`....
	0x00c0:  0000 0000 0010 2606 4700 4400 0000 0000  ......&.G.D.....
	0x00d0:  0000 6812 25e4                           ..h.%.
2024-02-12 21:22:48.786459 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.33874: 48847- 3/0/0 CNAME chat.openai.com.cdn.cloudflare.net., A 172.64.150.28, A 104.18.37.228 (162)
	0x0000:  4500 00be 39e8 0000 8011 a237 ac19 0001  E...9......7....
	0x0010:  ac19 05dc 0035 8452 00aa 016f becf 8100  .....5.R...o....
	0x0020:  0001 0003 0000 0000 0463 6861 7406 6f70  .........chat.op
	0x0030:  656e 6169 0363 6f6d 0000 0100 0104 6368  enai.com......ch
	0x0040:  6174 066f 7065 6e61 6903 636f 6d00 0005  at.openai.com...
	0x0050:  0001 0000 0000 0024 0463 6861 7406 6f70  .......$.chat.op
	0x0060:  656e 6169 0363 6f6d 0363 646e 0a63 6c6f  enai.com.cdn.clo
	0x0070:  7564 666c 6172 6503 6e65 7400 0463 6861  udflare.net..cha
	0x0080:  7406 6f70 656e 6169 0363 6f6d 0363 646e  t.openai.com.cdn
	0x0090:  0a63 6c6f 7564 666c 6172 6503 6e65 7400  .cloudflare.net.
	0x00a0:  0001 0001 0000 0000 0004 ac40 961c c060  ...........@...`
	0x00b0:  0001 0001 0000 0000 0004 6812 25e4       ..........h.%.
2024-02-12 21:22:48.793057 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.50585: 32065 0/1/0 (124)
	0x0000:  4500 0098 39e9 0000 8011 a25c ac19 0001  E...9......\....
	0x0010:  ac19 05dc 0035 c599 0084 fbdd 7d41 8180  .....5......}A..
	0x0020:  0001 0000 0001 0000 0665 7665 6e74 730a  .........events.
	0x0030:  7374 6174 7369 6761 7069 036e 6574 0000  statsigapi.net..
	0x0040:  1c00 01c0 1300 0600 0100 0001 5e00 4907  ............^.I.
	0x0050:  6e73 2d31 3333 3609 6177 7364 6e73 2d33  ns-1336.awsdns-3
	0x0060:  3903 6f72 6700 1161 7773 646e 732d 686f  9.org..awsdns-ho
	0x0070:  7374 6d61 7374 6572 0661 6d61 7a6f 6e03  stmaster.amazon.
	0x0080:  636f 6d00 0000 0001 0000 1c20 0000 0384  com.............
	0x0090:  0012 7500 0001 5180                      ..u...Q.
2024-02-12 21:22:50.471283 eth0  In  IP LAPTOP-M41GA6ID.domain > 172.25.5.220.46410: 40627 NXDomain 0/0/0 (43)
	0x0000:  4500 0047 39ea 0000 8011 a2ac ac19 0001  E..G9...........
	0x0010:  ac19 05dc 0035 b54a 0033 aea9 9eb3 8183  .....5.J.3......
	0x0020:  0001 0000 0000 0000 0332 3230 0135 0232  .........220.5.2
	0x0030:  3503 3137 3207 696e 2d61 6464 7204 6172  5.172.in-addr.ar
	0x0040:  7061 0000 0c00 01                        pa.....
2024-02-12 21:22:50.744982 eth0  Out IP 172.25.5.220.58557 > LAPTOP-M41GA6ID.domain: 28804+ A? cdn.oaistatic.com. (35)
	0x0000:  4500 003f bb0a 4000 4011 2194 ac19 05dc  E..?..@.@.!.....
	0x0010:  ac19 0001 e4bd 0035 002b 5e4c 7084 0100  .......5.+^Lp...
	0x0020:  0001 0000 0000 0000 0363 646e 096f 6169  .........cdn.oai
	0x0030:  7374 6174 6963 0363 6f6d 0000 0100 01    static.com.....
2024-02-12 21:22:50.744997 eth0  Out IP 172.25.5.220.58557 > LAPTOP-M41GA6ID.domain: 24989+ AAAA? cdn.oaistatic.com. (35)
	0x0000:  4500 003f bb0b 4000 4011 2193 ac19 05dc  E..?..@.@.!.....
	0x0010:  ac19 0001 e4bd 0035 002b 5e4c 619d 0100  .......5.+^La...
	0x0020:  0001 0000 0000 0000 0363 646e 096f 6169  .........cdn.oai
	0x0030:  7374 6174 6963 0363 6f6d 0000 1c00 01    static.com.....
2024-02-12 21:22:50.745360 eth0  Out IP 172.25.5.220.54285 > LAPTOP-M41GA6ID.domain: 37006+ A? js.intercomcdn.com. (36)
	0x0000:  4500 0040 8f4c 4000 4011 4d51 ac19 05dc  E..@.L@.@.MQ....
	0x0010:  ac19 0001 d40d 0035 002c 5e4d 908e 0100  .......5.,^M....
	0x0020:  0001 0000 0000 0000 026a 730b 696e 7465  .........js.inte
	0x0030:  7263 6f6d 6364 6e03 636f 6d00 0001 0001  rcomcdn.com.....
2024-02-12 21:22:50.745373 eth0  Out IP 172.25.5.220.54285 > LAPTOP-M41GA6ID.domain: 33922+ AAAA? js.intercomcdn.com. (36)
	0x0000:  4500 0040 8f4d 4000 4011 4d50 ac19 05dc  E..@.M@.@.MP....
	0x0010:  ac19 0001 d40d 0035 002c 5e4d 8482 0100  .......5.,^M....
	0x0020:  0001 0000 0000 0000 026a 730b 696e 7465  .........js.inte
	0x0030:  7263 6f6d 6364 6e03 636f 6d00 001c 0001  rcomcdn.com.....
2024-02-12 21:22:50.746010 eth0  Out IP 172.25.5.220.33190 > LAPTOP-M41GA6ID.domain: 23688+ A? tcr9i.chat.openai.com. (39)
	0x0000:  4500 0043 d02e 4000 4011 0c6c ac19 05dc  E..C..@.@..l....
	0x0010:  ac19 0001 81a6 0035 002f 5e50 5c88 0100  .......5./^P\...
	0x0020:  0001 0000 0000 0000 0574 6372 3969 0463  .........tcr9i.c
	0x0030:  6861 7406 6f70 656e 6169 0363 6f6d 0000  hat.openai.com..
	0x0040:  0100 01    
    ```

### Task 2: Perform a tcpdump capture where you capture TCP packets that are destined for either port 443 or 8080, and originate from your computer.  

I approached this in two ideas.  Maybe I don't have to specify the src host, maybe i do.  Turns out i do to get more precise data.  All the traffic that is coming to the WSL Kali is coming via the host, because it is running as a guest on the host machine. Perhaps that is less true than I thought. Then again, the VM is using the host's physical hardware, and it doesn't have a bridge setup (Its not native Linux-the host).  So maybe running: 'sudo tcpdump -i any -n -tttt -xx -X -c 30 tcp and \(dst port 443 or dst port 8080\) >| tcporrt.txt'  will give the right response.  
Here is what the flags are:     
    -sudo tcpdump: Executes the tcpdump tool with elevated privileges using sudo.
    -i any:  Like the command above, it specifies the network interface to capture packets from. In this case, any is used to capture from all available interfaces.
    -n: Disables DNS resolution for IP addresses and port numbers. Displays numerical values instead of resolving them to hostnames or service names.
    -tttt: Displays timestamps in Unix epoch format for each packet.
    -xx: Prints the hexadecimal and ASCII representation of the packet data.
    -X: Displays data about each packet in both hexadecimal and ASCII formats.
    -c 30: Limits the capture to the first 30 packets that match the specs.
    tcp: Filters packets to capture only TCP packets.
    and \(dst port 443 or dst port 8080\): Further filters TCP packets to capture only those that are destined for either port 443 or 8080. I am pretty sure this is the right way to escape.
    >| tcport.txt: Redirects the output to a file named tcport.txt. The > operator is used for redirection, and >| is used to forcefully overwrite the file if it already exists.

    

``` 
2024-02-12 21:52:17.157455 eth0  Out IP 172.25.5.220.39974 > 185.199.108.133.443: Flags [P.], seq 2340225176:2340225215, ack 3741944099, win 501, options [nop,nop,TS val 414790711 ecr 1389058377], length 39
	0x0000:  4500 005b 2444 4000 4006 3e17 ac19 05dc  E..[$D@.@.>.....
	0x0010:  b9c7 6c85 9c26 01bb 8b7d 0098 df09 8923  ..l..&...}.....#
	0x0020:  8018 01f5 d88f 0000 0101 080a 18b9 3437  ..............47
	0x0030:  52cb 5949 1703 0300 22db 4d97 0520 e666  R.YI....".M....f
	0x0040:  186d debc 9f75 d5f6 536d bd67 0fdd 963c  .m...u..Sm.g...<
	0x0050:  d116 5eb4 8d3a 575e e8fe a7              ..^..:W^...
2024-02-12 21:52:17.157577 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [P.], seq 2990511083:2990511122, ack 171529589, win 501, options [nop,nop,TS val 414790711 ecr 36775800], length 39
	0x0000:  4500 005b ff31 4000 4006 6329 ac19 05dc  E..[.1@.@.c)....
	0x0010:  b9c7 6c85 9c32 01bb b23f 93eb 0a39 5575  ..l..2...?...9Uu
	0x0020:  8018 01f5 d88f 0000 0101 080a 18b9 3437  ..............47
	0x0030:  0231 2778 1703 0300 22b8 9368 0a3a dbb3  .1'x...."..h.:..
	0x0040:  1822 3c93 0bc4 6af8 caf6 55d2 5686 3b2f  ."<...j...U.V.;/
	0x0050:  185c ab0d cf25 c857 5cde ee              .\...%.W\..
2024-02-12 21:52:17.157653 eth0  Out IP 172.25.5.220.51448 > 185.199.110.154.443: Flags [P.], seq 114779762:114779801, ack 1947869654, win 501, options [nop,nop,TS val 1325946017 ecr 828604699], length 39
	0x0000:  4500 005b cef9 4000 4006 914c ac19 05dc  E..[..@.@..L....
	0x0010:  b9c7 6e9a c8f8 01bb 06d7 6672 741a 21d6  ..n.......frt.!.
	0x0020:  8018 01f5 daa4 0000 0101 080a 4f08 54a1  ............O.T.
	0x0030:  3163 811b 1703 0300 22c5 da2f 8dca c526  1c......"../...&
	0x0040:  4bf7 631f 7b4a 6f29 2f77 833a 5c50 051e  K.c.{Jo)/w.:\P..
	0x0050:  4aa7 75f0 3df4 09ca e6d2 ec              J.u.=......
2024-02-12 21:52:17.157731 eth0  Out IP 172.25.5.220.51454 > 185.199.110.154.443: Flags [P.], seq 2989151091:2989151130, ack 2617965356, win 501, options [nop,nop,TS val 1325946017 ecr 3129154373], length 39
	0x0000:  4500 005b bd7f 4000 4006 a2c6 ac19 05dc  E..[..@.@.......
	0x0010:  b9c7 6e9a c8fe 01bb b22a d373 9c0a fb2c  ..n......*.s...,
	0x0020:  8018 01f5 daa4 0000 0101 080a 4f08 54a1  ............O.T.
	0x0030:  ba83 1b45 1703 0300 2271 b7c0 167b 2b5b  ...E...."q...{+[
	0x0040:  08af 6c1c 78bb 2b9d 37c0 c361 7fce d273  ..l.x.+.7..a...s
	0x0050:  859a 455b 2b51 09f4 fc36 3c              ..E[+Q...6<
2024-02-12 21:52:17.158382 eth0  Out IP 172.25.5.220.51448 > 185.199.110.154.443: Flags [FP.], seq 39:63, ack 1, win 501, options [nop,nop,TS val 1325946017 ecr 828604699], length 24
	0x0000:  4500 004c cefa 4000 4006 915a ac19 05dc  E..L..@.@..Z....
	0x0010:  b9c7 6e9a c8f8 01bb 06d7 6699 741a 21d6  ..n.......f.t.!.
	0x0020:  8019 01f5 da95 0000 0101 080a 4f08 54a1  ............O.T.
	0x0030:  3163 811b 1703 0300 1356 4bdb 94d8 4df2  1c.......VK...M.
	0x0040:  7d94 681e daf8 3ea7 2a5e d812            }.h...>.*^..
2024-02-12 21:52:17.159047 eth0  Out IP 172.25.5.220.51454 > 185.199.110.154.443: Flags [P.], seq 39:63, ack 1, win 501, options [nop,nop,TS val 1325946018 ecr 3129154373], length 24
	0x0000:  4500 004c bd80 4000 4006 a2d4 ac19 05dc  E..L..@.@.......
	0x0010:  b9c7 6e9a c8fe 01bb b22a d39a 9c0a fb2c  ..n......*.....,
	0x0020:  8018 01f5 da95 0000 0101 080a 4f08 54a2  ............O.T.
	0x0030:  ba83 1b45 1703 0300 13c9 2658 108c 948d  ...E......&X....
	0x0040:  d6d6 55c8 7cd2 98cf 9b79 74fb            ..U.|....yt.
2024-02-12 21:52:17.159076 eth0  Out IP 172.25.5.220.51454 > 185.199.110.154.443: Flags [F.], seq 63, ack 1, win 501, options [nop,nop,TS val 1325946018 ecr 3129154373], length 0
	0x0000:  4500 0034 bd81 4000 4006 a2eb ac19 05dc  E..4..@.@.......
	0x0010:  b9c7 6e9a c8fe 01bb b22a d3b2 9c0a fb2c  ..n......*.....,
	0x0020:  8011 01f5 da7d 0000 0101 080a 4f08 54a2  .....}......O.T.
	0x0030:  ba83 1b45                                ...E
2024-02-12 21:52:17.159711 eth0  Out IP 172.25.5.220.39974 > 185.199.108.133.443: Flags [P.], seq 39:63, ack 1, win 501, options [nop,nop,TS val 414790713 ecr 1389058377], length 24
	0x0000:  4500 004c 2445 4000 4006 3e25 ac19 05dc  E..L$E@.@.>%....
	0x0010:  b9c7 6c85 9c26 01bb 8b7d 00bf df09 8923  ..l..&...}.....#
	0x0020:  8018 01f5 d880 0000 0101 080a 18b9 3439  ..............49
	0x0030:  52cb 5949 1703 0300 13bd f2e1 0c8e 98b0  R.YI............
	0x0040:  1d0d afad 43dc 8156 8baf f42a            ....C..V...*
2024-02-12 21:52:17.159743 eth0  Out IP 172.25.5.220.39974 > 185.199.108.133.443: Flags [F.], seq 63, ack 1, win 501, options [nop,nop,TS val 414790713 ecr 1389058377], length 0
	0x0000:  4500 0034 2446 4000 4006 3e3c ac19 05dc  E..4$F@.@.><....
	0x0010:  b9c7 6c85 9c26 01bb 8b7d 00d7 df09 8923  ..l..&...}.....#
	0x0020:  8011 01f5 d868 0000 0101 080a 18b9 3439  .....h........49
	0x0030:  52cb 5949                                R.YI
2024-02-12 21:52:17.160257 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [P.], seq 39:63, ack 1, win 501, options [nop,nop,TS val 414790713 ecr 36775800], length 24
	0x0000:  4500 004c ff32 4000 4006 6337 ac19 05dc  E..L.2@.@.c7....
	0x0010:  b9c7 6c85 9c32 01bb b23f 9412 0a39 5575  ..l..2...?...9Uu
	0x0020:  8018 01f5 d880 0000 0101 080a 18b9 3439  ..............49
	0x0030:  0231 2778 1703 0300 132e 2300 eb03 0628  .1'x......#....(
	0x0040:  aa50 179e c53e da22 afe5 a326            .P...>."...&
2024-02-12 21:52:17.160300 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [F.], seq 63, ack 1, win 501, options [nop,nop,TS val 414790713 ecr 36775800], length 0
	0x0000:  4500 0034 ff33 4000 4006 634e ac19 05dc  E..4.3@.@.cN....
	0x0010:  b9c7 6c85 9c32 01bb b23f 942a 0a39 5575  ..l..2...?.*.9Uu
	0x0020:  8011 01f5 d868 0000 0101 080a 18b9 3439  .....h........49
	0x0030:  0231 2778                                .1'x
2024-02-12 21:52:17.191690 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [P.], seq 0:63, ack 1, win 501, options [nop,nop,TS val 414790745 ecr 36828596], length 63
	0x0000:  4500 0073 ff34 4000 4006 630e ac19 05dc  E..s.4@.@.c.....
	0x0010:  b9c7 6c85 9c32 01bb b23f 93eb 0a39 5575  ..l..2...?...9Uu
	0x0020:  8018 01f5 d8a7 0000 0101 080a 18b9 3459  ..............4Y
	0x0030:  0231 f5b4 1703 0300 22b8 9368 0a3a dbb3  .1......"..h.:..
	0x0040:  1822 3c93 0bc4 6af8 caf6 55d2 5686 3b2f  ."<...j...U.V.;/
	0x0050:  185c ab0d cf25 c857 5cde ee17 0303 0013  .\...%.W\.......
	0x0060:  2e23 00eb 0306 28aa 5017 9ec5 3eda 22af  .#....(.P...>.".
	0x0070:  e5a3 26                                  ..&
2024-02-12 21:52:17.191822 eth0  Out IP 172.25.5.220.39974 > 185.199.108.133.443: Flags [R], seq 2340225240, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 628e ac19 05dc  E..(..@.@.b.....
	0x0010:  b9c7 6c85 9c26 01bb 8b7d 00d8 0000 0000  ..l..&...}......
	0x0020:  5004 0000 ad67 0000                      P....g..
2024-02-12 21:52:17.191824 eth0  Out IP 172.25.5.220.51454 > 185.199.110.154.443: Flags [R], seq 2989151155, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 6079 ac19 05dc  E..(..@.@.`y....
	0x0010:  b9c7 6e9a c8fe 01bb b22a d3b3 0000 0000  ..n......*......
	0x0020:  5004 0000 84f1 0000                      P.......
2024-02-12 21:52:17.191866 eth0  Out IP 172.25.5.220.51454 > 185.199.110.154.443: Flags [R], seq 2989151155, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 6079 ac19 05dc  E..(..@.@.`y....
	0x0010:  b9c7 6e9a c8fe 01bb b22a d3b3 0000 0000  ..n......*......
	0x0020:  5004 0000 84f1 0000                      P.......
2024-02-12 21:52:17.192271 eth0  Out IP 172.25.5.220.39974 > 185.199.108.133.443: Flags [R], seq 2340225240, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 628e ac19 05dc  E..(..@.@.b.....
	0x0010:  b9c7 6c85 9c26 01bb 8b7d 00d8 0000 0000  ..l..&...}......
	0x0020:  5004 0000 ad67 0000                      P....g..
2024-02-12 21:52:17.192563 eth0  Out IP 172.25.5.220.51448 > 185.199.110.154.443: Flags [R], seq 114779826, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 6079 ac19 05dc  E..(..@.@.`y....
	0x0010:  b9c7 6e9a c8f8 01bb 06d7 66b2 0000 0000  ..n.......f.....
	0x0020:  5004 0000 9d4c 0000                      P....L..
2024-02-12 21:52:17.192576 eth0  Out IP 172.25.5.220.51448 > 185.199.110.154.443: Flags [R], seq 114779826, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 6079 ac19 05dc  E..(..@.@.`y....
	0x0010:  b9c7 6e9a c8f8 01bb 06d7 66b2 0000 0000  ..n.......f.....
	0x0020:  5004 0000 9d4c 0000                      P....L..
2024-02-12 21:52:17.193478 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [R], seq 2990511147, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 628e ac19 05dc  E..(..@.@.b.....
	0x0010:  b9c7 6c85 9c32 01bb b23f 942b 0000 0000  ..l..2...?.+....
	0x0020:  5004 0000 f345 0000                      P....E..
2024-02-12 21:52:17.194338 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [R], seq 2990511147, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 628e ac19 05dc  E..(..@.@.b.....
	0x0010:  b9c7 6c85 9c32 01bb b23f 942b 0000 0000  ..l..2...?.+....
	0x0020:  5004 0000 f345 0000                      P....E..
2024-02-12 21:52:17.207339 eth0  Out IP 172.25.5.220.51454 > 185.199.110.154.443: Flags [R], seq 2989151155, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 6079 ac19 05dc  E..(..@.@.`y....
	0x0010:  b9c7 6e9a c8fe 01bb b22a d3b3 0000 0000  ..n......*......
	0x0020:  5004 0000 84f1 0000                      P.......
2024-02-12 21:52:17.209931 eth0  Out IP 172.25.5.220.39974 > 185.199.108.133.443: Flags [R], seq 2340225240, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 628e ac19 05dc  E..(..@.@.b.....
	0x0010:  b9c7 6c85 9c26 01bb 8b7d 00d8 0000 0000  ..l..&...}......
	0x0020:  5004 0000 ad67 0000                      P....g..
2024-02-12 21:52:17.210140 eth0  Out IP 172.25.5.220.51448 > 185.199.110.154.443: Flags [R], seq 114779826, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 6079 ac19 05dc  E..(..@.@.`y....
	0x0010:  b9c7 6e9a c8f8 01bb 06d7 66b2 0000 0000  ..n.......f.....
	0x0020:  5004 0000 9d4c 0000                      P....L..
2024-02-12 21:52:17.218924 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [R], seq 2990511147, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 628e ac19 05dc  E..(..@.@.b.....
	0x0010:  b9c7 6c85 9c32 01bb b23f 942b 0000 0000  ..l..2...?.+....
	0x0020:  5004 0000 f345 0000                      P....E..
2024-02-12 21:52:17.229619 eth0  Out IP 172.25.5.220.39986 > 185.199.108.133.443: Flags [R], seq 2990511147, win 0, length 0
	0x0000:  4500 0028 0000 4000 4006 628e ac19 05dc  E..(..@.@.b.....
	0x0010:  b9c7 6c85 9c32 01bb b23f 942b 0000 0000  ..l..2...?.+....
	0x0020:  5004 0000 f345 0000                      P....E..
2024-02-12 21:52:20.159619 eth0  Out IP 172.25.5.220.52868 > 104.18.4.159.443: Flags [P.], seq 4117597336:4117597375, ack 2486467044, win 501, options [nop,nop,TS val 1626740886 ecr 871363660], length 39
	0x0000:  4500 005b 070b 4000 4006 14ec ac19 05dc  E..[..@.@.......
	0x0010:  6812 049f ce84 01bb f56d 8c98 9434 79e4  h........m...4y.
	0x0020:  8018 01f5 1ef4 0000 0101 080a 60f6 1896  ............`...
	0x0030:  33ef f44c 1703 0300 2239 eb5d 6170 130a  3..L...."9.]ap..
	0x0040:  b7d0 30ac 6b3b a572 08ad 0b0e 9ad0 6012  ..0.k;.r......`.
	0x0050:  8bde b056 646e 339b dfa2 86              ...Vdn3....
2024-02-12 21:52:20.160387 eth0  Out IP 172.25.5.220.52868 > 104.18.4.159.443: Flags [P.], seq 39:63, ack 1, win 501, options [nop,nop,TS val 1626740886 ecr 871363660], length 24
	0x0000:  4500 004c 070c 4000 4006 14fa ac19 05dc  E..L..@.@.......
	0x0010:  6812 049f ce84 01bb f56d 8cbf 9434 79e4  h........m...4y.
	0x0020:  8018 01f5 1ee5 0000 0101 080a 60f6 1896  ............`...
	0x0030:  33ef f44c 1703 0300 1300 705a 7f58 d6a3  3..L......pZ.X..
	0x0040:  6e00 8bf4 5625 01f0 815b ebb1            n...V%...[..
2024-02-12 21:52:20.160439 eth0  Out IP 172.25.5.220.52868 > 104.18.4.159.443: Flags [F.], seq 63, ack 1, win 501, options [nop,nop,TS val 1626740887 ecr 871363660], length 0
	0x0000:  4500 0034 070d 4000 4006 1511 ac19 05dc  E..4..@.@.......
	0x0010:  6812 049f ce84 01bb f56d 8cd7 9434 79e4  h........m...4y.
	0x0020:  8011 01f5 1ecd 0000 0101 080a 60f6 1897  ............`...
	0x0030:  33ef f44c                                3..L
2024-02-12 21:52:20.183537 eth0  Out IP 172.25.5.220.52868 > 104.18.4.159.443: Flags [.], ack 2, win 501, options [nop,nop,TS val 1626740910 ecr 871416453], length 0
	0x0000:  4500 0034 0000 4000 4006 1c1e ac19 05dc  E..4..@.@.......
	0x0010:  6812 049f ce84 01bb f56d 8cd8 9434 79e5  h........m...4y.
	0x0020:  8010 01f5 8567 0000 0101 080a 60f6 18ae  .....g......`...
	0x0030:  33f0 c285                                3...
2024-02-12 21:52:22.371503 eth0  Out IP 172.25.5.220.33944 > 34.117.237.239.443: Flags [P.], seq 3630336362:3630336401, ack 1143948924, win 501, options [nop,nop,TS val 1457677722 ecr 1838959173], length 39
	0x0000:  4500 005b 919c 4000 4006 e6a6 ac19 05dc  E..[..@.@.......
	0x0010:  2275 edef 8498 01bb d862 896a 442f 467c  "u.......b.jD/F|
	0x0020:  8018 01f5 c2a7 0000 0101 080a 56e2 659a  ............V.e.
	0x0030:  6d9c 4a45 1703 0300 2205 2cc6 331f 7035  m.JE....".,.3.p5
	0x0040:  3c33 e062 693c 9c3f 36b9 ac7c f8e9 b5a2  <3.bi<.?6..|....
	0x0050:  ba2d e568 3b64 3546 bdfb 33              .-.h;d5F..3
```
Those results are suspect. All (most) the traffic is coming out, and it is coming from the IP address of the VM. That's not what I am looking for.  But maybe it is what I am looking for.  Per the documents (wsl), wsl uses a virtual switch to virtualize the laptop hardware.  WSL commonly uses a virtual network adapter to communicate with the Windows host machine, and if you run 'wsl ip addr' in the windows side, you get 172.25.5.220.  So that looks good. 

### TASK 3  Perform a tcpdump capture where traffic is either UDP or TCP, is inbound to your computer, and destined for a port between 20000 and 35000.

First glance at this and i thought i could just essentially amend the previous commands and add a 'portrange', like this: 'sudo tcpdump -i any -n -tttt -xx -X -c 30 \(tcp or udp\) dst portrange 20000-35000'.   That was a no-go. Apparently diffent versions of tcpdump work differently.  Then i bashed around and eventually got to this: 'sudo tcpdump -i any -n -tttt -xx -c 30 -X \(tcp dst portrange 20000-35000 or udp dst portrange 20000-35000\) >| task3.txt'.  The flags are as explained in the commands above. (Task 1 and 2)  The port range was just found from just bashing around.  Googling 'get range of ports tcpdump' got me in the right direction and let me know portrange existed. Its not documented on the tcpdump man page very well.  Nmap might be a little more useful in this case.  Anyways. Heres the dump.

```
2024-02-12 22:30:46.470910 eth0  In  IP 192.30.255.117.443 > 172.25.5.220.32770: Flags [P.], seq 3437156121:3437156160, ack 2147030607, win 165, options [nop,nop,TS val 2864985606 ecr 4003994401], length 39
	0x0000:  4500 005b 276e 4000 3306 aea5 c01e ff75  E..['n@.3......u
	0x0010:  ac19 05dc 01bb 8002 ccde d719 7ff9 164f  ...............O
	0x0020:  8018 00a5 74f3 0000 0101 080a aac4 3606  ....t.........6.
	0x0030:  eea8 1b21 1703 0300 22f3 533c fb16 e982  ...!....".S<....
	0x0040:  4a14 98fc 14fa 8493 15c8 b595 0501 c482  J...............
	0x0050:  49c2 feb9 7c4f 1b30 918f f1              I...|O.0...
2024-02-12 22:30:46.470911 eth0  In  IP 192.30.255.117.443 > 172.25.5.220.32770: Flags [P.], seq 39:63, ack 1, win 165, options [nop,nop,TS val 2864985606 ecr 4003994401], length 24
	0x0000:  4500 004c 276f 4000 3306 aeb3 c01e ff75  E..L'o@.3......u
	0x0010:  ac19 05dc 01bb 8002 ccde d740 7ff9 164f  ...........@...O
	0x0020:  8018 00a5 6b29 0000 0101 080a aac4 3606  ....k)........6.
	0x0030:  eea8 1b21 1703 0300 138c 910f 143e 68ac  ...!.........>h.
	0x0040:  364c c1ce 3429 2397 84d7 e24e            6L..4)#....N
2024-02-12 22:30:46.470911 eth0  In  IP 192.30.255.117.443 > 172.25.5.220.32770: Flags [F.], seq 63, ack 1, win 165, options [nop,nop,TS val 2864985606 ecr 4003994401], length 0
	0x0000:  4500 0034 2770 4000 3306 aeca c01e ff75  E..4'p@.3......u
	0x0010:  ac19 05dc 01bb 8002 ccde d758 7ff9 164f  ...........X...O
	0x0020:  8011 00a5 5dbb 0000 0101 080a aac4 3606  ....].........6.
	0x0030:  eea8 1b21                                ...!
2024-02-12 22:30:46.479887 eth0  In  IP 192.30.255.117.443 > 172.25.5.220.32770: Flags [R], seq 3437156185, win 0, length 0
	0x0000:  4500 0028 0000 4000 3306 d646 c01e ff75  E..(..@.3..F...u
	0x0010:  ac19 05dc 01bb 8002 ccde d759 0000 0000  ...........Y....
	0x0020:  5004 0000 1861 0000                      P....a..
2024-02-12 22:30:47.256028 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [.], ack 291118111, win 128, options [nop,nop,TS val 3229569877 ecr 1443970467], length 0
	0x0000:  4500 0034 499f 4000 2206 60c8 8c52 7015  E..4I.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 67ed 115a 1c1f  .......`..g..Z..
	0x0020:  8010 0080 382a 0000 0101 080a c07f 5355  ....8*........SU
	0x0030:  5611 3da3                                V.=.
2024-02-12 22:30:47.256029 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 0:48, ack 1, win 128, options [nop,nop,TS val 3229569877 ecr 1443970467], length 48
	0x0000:  4500 0064 49a0 4000 2206 6097 8c52 7015  E..dI.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 67ed 115a 1c1f  .......`..g..Z..
	0x0020:  8018 0080 1271 0000 0101 080a c07f 5355  .....q........SU
	0x0030:  5611 3da3 1703 0300 2b97 3774 a648 e2f3  V.=.....+.7t.H..
	0x0040:  70fd e7bf e7f0 b1b4 caac 53bf 0481 7259  p.........S...rY
	0x0050:  c9d3 d001 d43d 5b44 f1a6 c9e0 541c d695  .....=[D....T...
	0x0060:  ad1e 3adc                                ..:.
2024-02-12 22:30:47.256029 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [.], ack 959, win 130, options [nop,nop,TS val 3229569878 ecr 1443970470], length 0
	0x0000:  4500 0034 49a1 4000 2206 60c6 8c52 7015  E..4I.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 681d 115a 1fdd  .......`..h..Z..
	0x0020:  8010 0082 3436 0000 0101 080a c07f 5356  ....46........SV
	0x0030:  5611 3da6                                V.=.
2024-02-12 22:30:47.256029 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 48:96, ack 959, win 130, options [nop,nop,TS val 3229569878 ecr 1443970470], length 48
	0x0000:  4500 0064 49a2 4000 2206 6095 8c52 7015  E..dI.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 681d 115a 1fdd  .......`..h..Z..
	0x0020:  8018 0082 b8ea 0000 0101 080a c07f 5356  ..............SV
	0x0030:  5611 3da6 1703 0300 2b47 22cc a4ca b5bd  V.=.....+G".....
	0x0040:  08dd eee1 3aad e532 f1ed 3d18 a618 ac86  ....:..2..=.....
	0x0050:  c4b0 79fd 6d82 6548 7bcb db2a 6db0 00ef  ..y.m.eH{..*m...
	0x0060:  99d8 ae48                                ...H
2024-02-12 22:30:47.258861 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 96:572, ack 959, win 130, options [nop,nop,TS val 3229569882 ecr 1443970470], length 476
	0x0000:  4500 0210 49a3 4000 2206 5ee8 8c52 7015  E...I.@.".^..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 684d 115a 1fdd  .......`..hM.Z..
	0x0020:  8018 0082 db0f 0000 0101 080a c07f 535a  ..............SZ
	0x0030:  5611 3da6 1703 0301 d745 cc35 0c44 ada7  V.=......E.5.D..
	0x0040:  1cb4 f0c7 2c6d 2927 747d 98c7 a496 9093  ....,m)'t}......
	0x0050:  6840 0c9e c920 341a 9752 4809 e30d 90d8  h@....4..RH.....
	0x0060:  d425 1614 b8f1 dcc2 6753 60ff a88e 60b5  .%......gS`...`.
	0x0070:  7190 0c42 01aa d07f 1679 ef08 7651 9e44  q..B.....y..vQ.D
	0x0080:  a426 dc2a 404a 0c31 f1b5 cfd0 bdeb b7f1  .&.*@J.1........
	0x0090:  a129 8626 5d1a a405 fe12 d6d8 7cfc e96a  .).&].......|..j
	0x00a0:  fee9 79ef e5d6 c1a5 7149 3608 63ba d711  ..y.....qI6.c...
	0x00b0:  4c1f a1d1 a534 df84 72d8 a0d1 21d6 b4ce  L....4..r...!...
	0x00c0:  8799 6c1d 258b 1794 7641 a6a6 16d9 af40  ..l.%...vA.....@
	0x00d0:  9789 ca8c 62a2 655d 741d d17e 4ceb 620d  ....b.e]t..~L.b.
	0x00e0:  8d6c cad0 5f23 f6de ffd5 48ba 417c 4a6b  .l.._#....H.A|Jk
	0x00f0:  b5fd bbdf 9c44 eba8 b0ad 2ced 75dc 87dc  .....D....,.u...
	0x0100:  1722 afda ba98 397a f0a7 32f3 8323 8ad8  ."....9z..2..#..
	0x0110:  27cf cf44 2859 27fb 974c 4918 a8b0 c066  '..D(Y'..LI....f
	0x0120:  bb30 58fa c539 f0fd 27d0 2f36 afb0 640b  .0X..9..'./6..d.
	0x0130:  b234 ef40 c351 5a43 337c 15db 80c1 c912  .4.@.QZC3|......
	0x0140:  881a 8880 1d41 2b52 6e52 b27c 4d94 8a05  .....A+RnR.|M...
	0x0150:  aeb4 5fbf aa32 9da5 b527 db81 3182 76ad  .._..2...'..1.v.
	0x0160:  12eb 0a58 9fa6 0dbd a756 8b59 89eb 56a0  ...X.....V.Y..V.
	0x0170:  5558 6cf0 57de b99d fe54 3e6c 9f12 55c2  UXl.W....T>l..U.
	0x0180:  4f87 5680 f298 dbb9 1f07 cdac d2a5 9a49  O.V............I
	0x0190:  548f 7b31 2564 f4aa 70c9 ce6c 0612 9981  T.{1%d..p..l....
	0x01a0:  5355 173d 0330 d752 af76 5ad0 0d5c d53b  SU.=.0.R.vZ..\.;
	0x01b0:  5bbe 2dab d458 f746 e105 ece9 c6ed 8acd  [.-..X.F........
	0x01c0:  9202 46c0 4187 a84c 3032 e342 ef8b 79d8  ..F.A..L02.B..y.
	0x01d0:  f249 f7d3 f7cc b1ee e14c ce0c ea48 4232  .I.......L...HB2
	0x01e0:  713e 0711 aa78 25f8 dc77 e88e dc67 cb04  q>...x%..w...g..
	0x01f0:  25f9 fd7f 0b61 ece8 ae34 6023 dbb4 f84b  %....a...4`#...K
	0x0200:  807c 4c36 adef 312b f5f2 87dd 80d8 546b  .|L6..1+......Tk
2024-02-12 22:30:47.259402 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 572:1048, ack 959, win 130, options [nop,nop,TS val 3229569883 ecr 1443970470], length 476
	0x0000:  4500 0210 49a4 4000 2206 5ee7 8c52 7015  E...I.@.".^..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6a29 115a 1fdd  .......`..j).Z..
	0x0020:  8018 0082 d171 0000 0101 080a c07f 535b  .....q........S[
	0x0030:  5611 3da6 1703 0301 d7af 5253 997a 2b1c  V.=.......RS.z+.
	0x0040:  a4ef 2ff5 4cd5 d0b6 41ea f167 5ba4 c2e7  ../.L...A..g[...
	0x0050:  bc3f 4751 e6b5 329a b3f0 7582 9be7 f6e3  .?GQ..2...u.....
	0x0060:  5394 9c19 89ac 570d 87a6 c674 54e6 2c8a  S.....W....tT.,.
	0x0070:  4ac1 e1ba 3870 20c5 904e 5a9d 340b 46f9  J...8p...NZ.4.F.
	0x0080:  bb69 51b6 90d6 663b df0c 707a b1fe 6f33  .iQ...f;..pz..o3
	0x0090:  2184 c6e5 0a03 28f6 ba5e 221b 4cf0 3c30  !.....(..^".L.<0
	0x00a0:  59a4 c328 e13c 37af 9ecd ab42 df7c d355  Y..(.<7....B.|.U
	0x00b0:  02f5 4dea d8e5 ac7c 7b7c 11a1 26a6 b012  ..M....|{|..&...
	0x00c0:  4ec3 35f6 81c6 7889 b14a ec63 d8b7 62e1  N.5...x..J.c..b.
	0x00d0:  626d c5fb 846d b236 d56e c7d3 bd27 423c  bm...m.6.n...'B<
	0x00e0:  c1b8 bad8 fd05 bf7d 8594 4590 bf4f d538  .......}..E..O.8
	0x00f0:  1598 a7cd 59f4 b864 3610 f4b0 57fe 8d57  ....Y..d6...W..W
	0x0100:  dc97 b08d b73c 95a6 b003 e54b 1d03 bf87  .....<.....K....
	0x0110:  07e1 22f0 5c7d 6f36 c692 2f5e 55cb ee9c  ..".\}o6../^U...
	0x0120:  11d5 415d a3ec c15b 4e82 c924 886b 6e19  ..A]...[N..$.kn.
	0x0130:  98c0 5030 37ee 411f 6c64 28a2 9373 3bee  ..P07.A.ld(..s;.
	0x0140:  1c51 c756 f8b4 835b 4c26 8852 d985 208c  .Q.V...[L&.R....
	0x0150:  244d 411f 9f10 16dc 6318 f380 1a75 59d4  $MA.....c....uY.
	0x0160:  70d3 27da 48f5 e3a9 9bde 6106 d64a 595f  p.'.H.....a..JY_
	0x0170:  71e6 8cfb 46b3 cf8d 6d3a 7310 83d1 973d  q...F...m:s....=
	0x0180:  bf99 eddc 3c96 1861 948f af06 3479 8115  ....<..a....4y..
	0x0190:  874b 0a77 7054 b75d 4fe9 0f8e b3d7 5d0d  .K.wpT.]O.....].
	0x01a0:  13d5 adc2 5cd0 9a90 41e4 c0b3 e470 2d92  ....\...A....p-.
	0x01b0:  578d f4ba 5807 65b1 24a4 e640 7c5a cdb7  W...X.e.$..@|Z..
	0x01c0:  3993 ec65 ad90 f914 b698 63be ebe8 e4bd  9..e......c.....
	0x01d0:  725e b763 714b c236 3855 3fb0 d6a0 9206  r^.cqK.68U?.....
	0x01e0:  0403 6e4f 399b 51dc fc6a 3bec c58a 6439  ..nO9.Q..j;...d9
	0x01f0:  1b5a 9339 cdeb 0765 a4ea 5531 890b 91f5  .Z.9...e..U1....
	0x0200:  b347 1417 c16b f187 7510 ca0e 27c3 3bb0  .G...k..u...'.;.
2024-02-12 22:30:47.556989 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [.], ack 1979, win 133, options [nop,nop,TS val 3229570179 ecr 1443970775], length 0
	0x0000:  4500 0034 49a5 4000 2206 60c2 8c52 7015  E..4I.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6c05 115a 23d9  .......`..l..Z#.
	0x0020:  8010 0085 29f1 0000 0101 080a c07f 5483  ....).........T.
	0x0030:  5611 3ed7                                V.>.
2024-02-12 22:30:47.556990 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 1048:1096, ack 1979, win 133, options [nop,nop,TS val 3229570179 ecr 1443970775], length 48
	0x0000:  4500 0064 49a6 4000 2206 6091 8c52 7015  E..dI.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6c05 115a 23d9  .......`..l..Z#.
	0x0020:  8018 0085 ece7 0000 0101 080a c07f 5483  ..............T.
	0x0030:  5611 3ed7 1703 0300 2be2 02d9 4993 51c0  V.>.....+...I.Q.
	0x0040:  10f8 732a 2350 5ef0 0259 c2de 3a82 ac9c  ..s*#P^..Y..:...
	0x0050:  eca3 1cc9 544a 0470 6847 6ca2 3d27 a4f8  ....TJ.phGl.='..
	0x0060:  8aca 020a                                ....
2024-02-12 22:30:47.561806 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 1096:1572, ack 1979, win 133, options [nop,nop,TS val 3229570185 ecr 1443970775], length 476
	0x0000:  4500 0210 49a7 4000 2206 5ee4 8c52 7015  E...I.@.".^..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6c35 115a 23d9  .......`..l5.Z#.
	0x0020:  8018 0085 3872 0000 0101 080a c07f 5489  ....8r........T.
	0x0030:  5611 3ed7 1703 0301 d7ce a5d1 0c2a 8cb4  V.>..........*..
	0x0040:  49d2 b6fb 94ca 0def f5dc ad00 5295 18fa  I...........R...
	0x0050:  11b9 832e f048 a7d5 cb58 d03b 4fb2 0a53  .....H...X.;O..S
	0x0060:  d639 fab8 b52b d972 15d2 3bea 2914 9e5b  .9...+.r..;.)..[
	0x0070:  87e5 bcca 007d 9483 4ca2 6653 79d8 8921  .....}..L.fSy..!
	0x0080:  b069 0f77 0a22 1b6d 5135 1d95 4416 5d03  .i.w.".mQ5..D.].
	0x0090:  568c 2333 25f4 9a02 20a4 88fe caa1 5e07  V.#3%.........^.
	0x00a0:  6445 b73a 08cb e4fc 4bdb d30c 305d ffe9  dE.:....K...0]..
	0x00b0:  a017 4e8d a581 6b0c 85dd 0d8d 7515 a6eb  ..N...k.....u...
	0x00c0:  d483 f747 bf7f 0846 0c52 2e72 4859 238f  ...G...F.R.rHY#.
	0x00d0:  9055 79a3 7e30 9b92 4f88 c8f0 bbc3 3195  .Uy.~0..O.....1.
	0x00e0:  ec28 f41d 0958 7094 82d2 2ffa 3a72 2fe7  .(...Xp.../.:r/.
	0x00f0:  c5f6 c7fb 2ca2 bbb9 c1de b07e c576 5fef  ....,......~.v_.
	0x0100:  3eaf 015c a666 d98d c74d fb83 bc84 2e51  >..\.f...M.....Q
	0x0110:  6cb2 7095 5b37 5a06 586e 2f5d 660f 08a9  l.p.[7Z.Xn/]f...
	0x0120:  82d1 33e4 0bd2 fc6c 6039 f898 bd74 d510  ..3....l`9...t..
	0x0130:  84e4 0232 70f0 73f5 7a38 b6ff a971 45c9  ...2p.s.z8...qE.
	0x0140:  68e9 0a5d f272 8067 e60c 56b2 efc0 66ec  h..].r.g..V...f.
	0x0150:  7dad f610 837b 2efe 10f6 feac 99f4 fdcf  }....{..........
	0x0160:  0aba 0c7e 98cd 1544 0880 be19 8531 c548  ...~...D.....1.H
	0x0170:  2e09 b394 0583 61a6 34d4 0d3b 75da 398e  ......a.4..;u.9.
	0x0180:  669f 7098 e956 130d 2709 b8b9 f3c4 75b3  f.p..V..'.....u.
	0x0190:  f2cd 6a17 f97e 380f 3e40 d643 363e 6e32  ..j..~8.>@.C6>n2
	0x01a0:  5702 be0f 65e4 9390 538f 8fe0 f39b b0a5  W...e...S.......
	0x01b0:  1fa8 6065 f31c a859 b216 0877 5e5e ec29  ..`e...Y...w^^.)
	0x01c0:  2266 bd4c 8034 ef25 dffd fbb8 9e5f ca90  "f.L.4.%....._..
	0x01d0:  b72f 479e f76a 8cf1 ecd0 ca37 631c 39ea  ./G..j.....7c.9.
	0x01e0:  c6c7 7abe 9543 e219 ae84 8aa0 f72f f07c  ..z..C......./.|
	0x01f0:  988a 3fcd b586 d953 f177 69fb 431d a9aa  ..?....S.wi.C...
	0x0200:  790b e737 dac3 668a c055 d14f b769 714e  y..7..f..U.O.iqN
2024-02-12 22:30:47.877869 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [.], ack 2790, win 135, options [nop,nop,TS val 3229570453 ecr 1443971049], length 0
	0x0000:  4500 0034 49a8 4000 2206 60bf 8c52 7015  E..4I.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6e11 115a 2704  .......`..n..Z'.
	0x0020:  8010 0087 2294 0000 0101 080a c07f 5595  ....".........U.
	0x0030:  5611 3fe9                                V.?.
2024-02-12 22:30:47.877869 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [.], ack 3509, win 137, options [nop,nop,TS val 3229570454 ecr 1443971049], length 0
	0x0000:  4500 0034 49a9 4000 2206 60be 8c52 7015  E..4I.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6e11 115a 29d3  .......`..n..Z).
	0x0020:  8010 0089 1fc2 0000 0101 080a c07f 5596  ..............U.
	0x0030:  5611 3fe9                                V.?.
2024-02-12 22:30:47.877869 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 1572:1620, ack 3509, win 137, options [nop,nop,TS val 3229570454 ecr 1443971049], length 48
	0x0000:  4500 0064 49aa 4000 2206 608d 8c52 7015  E..dI.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6e11 115a 29d3  .......`..n..Z).
	0x0020:  8018 0089 7951 0000 0101 080a c07f 5596  ....yQ........U.
	0x0030:  5611 3fe9 1703 0300 2b58 c3cf cfbf 727f  V.?.....+X....r.
	0x0040:  9057 764e 1020 a729 9574 d359 46a9 b62e  .WvN...).t.YF...
	0x0050:  7fc4 98e8 46f4 7ffa 97df ca06 0aae 09d9  ....F...........
	0x0060:  2946 b7e8                                )F..
2024-02-12 22:30:47.877870 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 1620:2096, ack 3509, win 137, options [nop,nop,TS val 3229570457 ecr 1443971049], length 476
	0x0000:  4500 0210 49ab 4000 2206 5ee0 8c52 7015  E...I.@.".^..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 6e41 115a 29d3  .......`..nA.Z).
	0x0020:  8018 0089 b6bd 0000 0101 080a c07f 5599  ..............U.
	0x0030:  5611 3fe9 1703 0301 d728 3744 28ed aa9b  V.?......(7D(...
	0x0040:  c351 6a87 99a0 2e45 d081 3129 23df 8196  .Qj....E..1)#...
	0x0050:  770d 34a6 c42d af73 d77a baa6 6342 2351  w.4..-.s.z..cB#Q
	0x0060:  dcbc 5f8f d2c5 f145 d8a3 4358 7f68 8628  .._....E..CX.h.(
	0x0070:  e851 4f29 187f fbef 487e c727 ed3f 60f2  .QO)....H~.'.?`.
	0x0080:  9942 f3b4 2bac 225f 4f23 0d06 6718 3049  .B..+."_O#..g.0I
	0x0090:  6331 815e 107c 9051 b55a 7ef9 527d 397a  c1.^.|.Q.Z~.R}9z
	0x00a0:  ca21 2f79 2e70 837a 326d 1943 985b acba  .!/y.p.z2m.C.[..
	0x00b0:  63b8 faf7 5fe9 ac32 054b dbf6 9b7a d1ac  c..._..2.K...z..
	0x00c0:  7211 e3d8 418f 938a f451 9d5b 0393 e6ec  r...A....Q.[....
	0x00d0:  24b3 4ee8 500f 5119 2438 1c9c 4cb4 f325  $.N.P.Q.$8..L..%
	0x00e0:  68e1 9b17 e8d6 9ae7 479d dfa4 127b d6ed  h.......G....{..
	0x00f0:  f7a9 392a a746 de2c 661f fd9e 48cc abfc  ..9*.F.,f...H...
	0x0100:  0383 9277 d018 a4ca 0512 7667 e12e 6309  ...w......vg..c.
	0x0110:  8143 365a 364c 598b 85ff 7d4f f4f8 127c  .C6Z6LY...}O...|
	0x0120:  ee83 48f0 23c1 5c1e a534 74d9 ab73 f172  ..H.#.\..4t..s.r
	0x0130:  1a1a 1ba6 9727 937d 70df 7e4e d329 0b17  .....'.}p.~N.)..
	0x0140:  adfc 6277 8d61 d60f 705c def9 6e02 a2a0  ..bw.a..p\..n...
	0x0150:  2697 7aac 7470 7002 46e0 0e0a cc96 b5ef  &.z.tpp.F.......
	0x0160:  e169 f3b6 5ab2 247d a858 c52f 560a f652  .i..Z.$}.X./V..R
	0x0170:  2644 5be0 4d08 577b bb9e 124c 4324 f298  &D[.M.W{...LC$..
	0x0180:  b10a be1a 1b67 669a d38b 57e8 97df 3f19  .....gf...W...?.
	0x0190:  9e81 f31d 66c9 22f5 07d0 206a 04db 1855  ....f."....j...U
	0x01a0:  6d50 d7c9 ae58 fd85 3ca9 ee75 22ef 234f  mP...X..<..u".#O
	0x01b0:  3249 8fb7 675d b685 080c 7b10 0d7d 366c  2I..g]....{..}6l
	0x01c0:  0802 7d45 e798 fd97 eed6 3579 6bd9 92dd  ..}E......5yk...
	0x01d0:  5414 22b6 f6da 46e5 c0cf 66fa 270c 223c  T."...F...f.'."<
	0x01e0:  69dd bd10 a142 0acd d1d7 40c3 d5e5 6a34  i....B....@...j4
	0x01f0:  8d16 e125 0d31 45d0 086f c20e 6881 953f  ...%.1E..o..h..?
	0x0200:  ad96 b4db 6d5c c211 d8a4 3f72 6f81 e0fe  ....m\....?ro...
2024-02-12 22:30:50.157090 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [S.], seq 71072054, ack 1655196689, win 65160, options [mss 1460,sackOK,TS val 3719012599 ecr 798482918,nop,wscale 7], length 0
	0x0000:  4500 003c 0000 4000 3606 f6eb 0565 9676  E..<..@.6....e.v
	0x0010:  ac19 05dc 01bb 8112 043c 7936 62a8 4c11  .........<y6b.L.
	0x0020:  a012 fe88 bc7b 0000 0204 05b4 0402 080a  .....{..........
	0x0030:  ddab a0f7 2f97 e1e6 0103 0307            ..../.......
2024-02-12 22:30:50.319478 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [.], ack 518, win 506, options [nop,nop,TS val 3719012761 ecr 798483078], length 0
	0x0000:  4500 0034 c62e 4000 3606 30c5 0565 9676  E..4..@.6.0..e.v
	0x0010:  ac19 05dc 01bb 8112 043c 7937 62a8 4e16  .........<y7b.N.
	0x0020:  8010 01fa e48f 0000 0101 080a ddab a199  ................
	0x0030:  2f97 e286                                /...
2024-02-12 22:30:50.325374 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [P.], seq 1:2897, ack 518, win 506, options [nop,nop,TS val 3719012768 ecr 798483078], length 2896
	0x0000:  4500 0b84 c62f 4000 3606 2574 0565 9676  E..../@.6.%t.e.v
	0x0010:  ac19 05dc 01bb 8112 043c 7937 62a8 4e16  .........<y7b.N.
	0x0020:  8018 01fa 4dd7 0000 0101 080a ddab a1a0  ....M...........
	0x0030:  2f97 e286 1603 0300 7a02 0000 7603 03bd  /.......z...v...
	0x0040:  c6d9 6784 99d8 7c55 a987 bd71 bd8d 6c6e  ..g...|U...q..ln
	0x0050:  ff57 f27f e77f 15f2 2208 91fe ed1e d020  .W......".......
	0x0060:  f4ca 7234 c7c0 b5d4 de75 2d2c 40b3 2d66  ..r4.....u-,@.-f
	0x0070:  6f53 1ce5 5117 45d1 41f9 2a8d 4d27 89b4  oS..Q.E.A.*.M'..
	0x0080:  1301 0000 2e00 2b00 0203 0400 3300 2400  ......+.....3.$.
	0x0090:  1d00 2038 5e96 24bc 187b 3596 ccd4 8416  ...8^.$..{5.....
	0x00a0:  5d73 3fee 2d95 433f 5d3f e580 3e00 1e67  ]s?.-.C?]?..>..g
	0x00b0:  1ffc 3814 0303 0001 0117 0303 002a 3ef6  ..8..........*>.
	0x00c0:  bed2 6f92 7c9a 70b2 8307 5f37 e887 e3a0  ..o.|.p..._7....
	0x00d0:  f8f2 8d15 81bf a3b5 43e8 30ee 16fa 42d7  ........C.0...B.
	0x00e0:  1a50 2041 f98b 2c81 1703 030d 8f67 5de0  .P.A..,......g].
	0x00f0:  a4f7 30ba 99ad 1179 43d5 3bca 39fd 5378  ..0....yC.;.9.Sx
	0x0100:  acef 5b14 651c b5cf 3121 a519 aa7b 8301  ..[.e...1!...{..
	0x0110:  be4b cc12 ef46 b9c8 cb06 9a89 21d0 ef2a  .K...F......!..*
	0x0120:  9adb fe12 5e72 2f9d 49ca 871b 348e 700a  ....^r/.I...4.p.
	0x0130:  36a8 630b bdbf 2c4f b1a0 c8ae 25b6 01cc  6.c...,O....%...
	0x0140:  3dcc 3e87 6541 c1fc c7d0 6f0f 8079 1fd7  =.>.eA....o..y..
	0x0150:  9d11 67fc 1d4c 1d8e e434 7fbd a377 43ab  ..g..L...4...wC.
	0x0160:  46f1 d3df 4585 8185 c0d6 b56d 01ad 09b2  F...E......m....
	0x0170:  00df b82a 7632 c170 945a a72d 8898 1169  ...*v2.p.Z.-...i
	0x0180:  a371 004f ab40 ddee 917e 5665 dba6 f05e  .q.O.@...~Ve...^
	0x0190:  18f4 73a4 58ea 60c2 ee05 0a87 4cf4 dde5  ..s.X.`.....L...
	0x01a0:  84a6 ed48 bb59 bc7c d9ad 0c91 566a c23f  ...H.Y.|....Vj.?
	0x01b0:  0c32 1c20 95aa e6f7 f09d 6897 f54b 1238  .2........h..K.8
	0x01c0:  f8e8 67af 9e59 5fe7 3af6 7567 850a 909c  ..g..Y_.:.ug....
	0x01d0:  f410 3c71 6e52 84b4 e938 f3e1 32f2 0fdf  ..<qnR...8..2...
	0x01e0:  9fa5 7112 d562 1ecc dd04 6bdc e48f 5c95  ..q..b....k...\.
	0x01f0:  3931 401e 8f49 1219 2fd9 11eb 7a36 4fcd  91@..I../...z6O.
	0x0200:  b1c7 fb5b b58b 1f0f 0f46 cf9d 2caa 3ca0  ...[.....F..,.<.
	0x0210:  cb8c 24da 6ac6 3b76 b90e 77f8 5699 557f  ..$.j.;v..w.V.U.
	0x0220:  d792 b046 538d 3123 70ed 3d93 768f 201a  ...FS.1#p.=.v...
	0x0230:  c214 1161 5eab 584c 4918 8fc5 dd58 4142  ...a^.XLI....XAB
	0x0240:  aa10 ee7d a221 1195 4402 7bea 3111 d953  ...}.!..D.{.1..S
	0x0250:  7a77 7f77 15a3 494c ae4d c399 c686 7ea8  zw.w..IL.M....~.
	0x0260:  5a26 4d98 e5d5 7cd4 fa3b 1b10 3e0f 0c31  Z&M...|..;..>..1
	0x0270:  e961 e7a2 219c 6ece 3d52 ecfc 0920 19f0  .a..!.n.=R......
	0x0280:  3210 d0e0 2f2b 294f 8481 e620 71e2 1f9e  2.../+)O....q...
	0x0290:  2029 4591 7858 2206 fe25 423a 6290 38b6  .)E.xX"..%B:b.8.
	0x02a0:  5d2e 2348 3183 658b 64bf fcc0 cbcc 31e3  ].#H1.e.d.....1.
	0x02b0:  3281 428c bcb2 7596 d0af efff ee8b a305  2.B...u.........
	0x02c0:  09f0 e2b0 3a20 6c29 0ecb b044 c23a 856f  ....:.l)...D.:.o
	0x02d0:  be20 69a1 71e8 8bdb 2128 fb32 c121 08ea  ..i.q...!(.2.!..
	0x02e0:  5779 3d5e c472 9405 2840 a9eb 2767 c6a4  Wy=^.r..(@..'g..
	0x02f0:  27f3 5b02 71f9 1955 6484 2fca 8c6f 56c5  '.[.q..Ud./..oV.
	0x0300:  ffb3 2fbc 1089 ffc4 ea5d 4b7b b12c 49d3  ../......]K{.,I.
	0x0310:  baf9 da22 589a df5f f7bb 396f 8eb9 727b  ..."X.._..9o..r{
	0x0320:  c756 cd46 c6d4 fb44 34f6 9541 7525 778c  .V.F...D4..Au%w.
	0x0330:  9cd6 5a02 8d2a df57 71b2 98e7 d00f 615d  ..Z..*.Wq.....a]
	0x0340:  8f26 8d0b c819 c623 42a2 12da 6442 fddd  .&.....#B...dB..
	0x0350:  2eb4 8bb2 7762 cf6a 3345 d3a9 719b 6cc7  ....wb.j3E..q.l.
	0x0360:  6ae3 c3d9 1fa4 4c3a f15d 07e6 38d9 1cf6  j.....L:.]..8...
	0x0370:  1b53 5a10 e0f1 10b7 7432 c676 2583 dddb  .SZ.....t2.v%...
	0x0380:  e049 393b 94d6 4dea d629 d1b7 9c62 53e4  .I9;..M..)...bS.
	0x0390:  2636 85f8 8a5c 421b 3d0e fa29 bd75 a646  &6...\B.=..).u.F
	0x03a0:  8339 1e19 2efc 7675 c892 e7f8 02bf 3c57  .9....vu......<W
	0x03b0:  0dd5 abbf a302 0e63 1be4 7af9 6e4f ef9d  .......c..z.nO..
	0x03c0:  dccc 1535 29c3 6f7a 246d debb 458e 4d6c  ...5).oz$m..E.Ml
	0x03d0:  b244 1925 469c 151f f742 4f3f e6d9 adbc  .D.%F....BO?....
	0x03e0:  1dd0 f89d 9fe4 8245 8195 08b9 a48c 1278  .......E.......x
	0x03f0:  0b9f 8784 9fb8 865e 2a2d e022 3999 71a7  .......^*-."9.q.
	0x0400:  be5f b3ba fcb5 e8fe 6dea 3508 ab09 e1d0  ._......m.5.....
	0x0410:  ba1a d7d1 6098 5042 cfc5 8b14 68a1 69da  ....`.PB....h.i.
	0x0420:  d6e4 4cab 1873 c4be ae48 7edf 1e31 0bf9  ..L..s...H~..1..
	0x0430:  e7c5 ea05 2916 23c4 27f0 89d5 2993 a651  ....).#.'...)..Q
	0x0440:  c3fc 3447 657e be88 3c29 d1d1 0a82 a027  ..4Ge~..<).....'
	0x0450:  817d e8c1 cab5 ca13 f334 ab25 d6ba b82f  .}.......4.%.../
	0x0460:  c466 f20f e90c eec8 1f01 35bc 369d 1214  .f........5.6...
	0x0470:  3f27 db17 c5c9 5889 aef3 f59e 0ab8 4d89  ?'....X.......M.
	0x0480:  1fcc 3f6a 51b2 4b5a 1cb1 8404 8341 0be1  ..?jQ.KZ.....A..
	0x0490:  b08b 2e2c c4d6 7932 18dd 7c1a 83a9 cb62  ...,..y2..|....b
	0x04a0:  893e deb1 65a1 cfd8 1879 ebc7 d868 491a  .>..e....y...hI.
	0x04b0:  34b9 521f fc4a 0475 e00d 5aa7 2065 07f9  4.R..J.u..Z..e..
	0x04c0:  89d0 afb8 36cd 9b71 3de5 85f0 23e4 27a5  ....6..q=...#.'.
	0x04d0:  5e3b cd85 a2de afcf 18cf fbf7 7816 8691  ^;..........x...
	0x04e0:  b96d df62 531a 758f 96c7 99a4 03d4 28ed  .m.bS.u.......(.
	0x04f0:  c143 0bd5 92a9 66fd 013b 2d1e 4832 be59  .C....f..;-.H2.Y
	0x0500:  63bd ff5d d700 727f 5109 0679 e1eb 450b  c..]..r.Q..y..E.
	0x0510:  3a79 ea3b 72da 6d47 ff92 40bf 18e7 d16e  :y.;r.mG..@....n
	0x0520:  9ff3 332c 4501 c15a fef7 db99 7660 93bb  ..3,E..Z....v`..
	0x0530:  45f6 b497 0dfd 788a 93c5 77f0 1179 484f  E.....x...w..yHO
	0x0540:  0af9 955b 0bc7 feaa fbb7 00a4 6f0e c812  ...[........o...
	0x0550:  c7f7 8585 f17e 0a26 4367 3014 a352 db62  .....~.&Cg0..R.b
	0x0560:  fe93 9d60 58e9 64e2 bb00 c2be e738 3204  ...`X.d......82.
	0x0570:  d944 a656 4a0d 1a8f f01e 1aec 7846 ad16  .D.VJ.......xF..
	0x0580:  916b 130e 7eb6 c01c f3be 63b8 5b3b c004  .k..~.....c.[;..
	0x0590:  eeb8 9b7f 2a1b e1c3 6012 de29 ca60 d41e  ....*...`..).`..
	0x05a0:  8d8b f8b3 8f7b 0de5 c896 d2ac 37d8 671e  .....{......7.g.
	0x05b0:  8b43 63d8 dd40 4c9d 42fa 3069 24b8 b964  .Cc..@L.B.0i$..d
	0x05c0:  bd96 49e5 1a62 d228 9653 7904 ee28 df39  ..I..b.(.Sy..(.9
	0x05d0:  2501 a8a3 4a1b 1d80 5fe6 8b5e 80f8 18e2  %...J..._..^....
	0x05e0:  e677 a5fe dd3e feb5 1acb afd1 07dd da9c  .w...>..........
	0x05f0:  09e5 0848 326d bb67 e5e8 b978 b072 a214  ...H2m.g...x.r..
	0x0600:  6885 ef47 2318 6840 7b74 3376 1505 9cc9  h..G#.h@{t3v....
	0x0610:  7d2f e360 c37c fcc2 9a2e 9b68 9fb0 462f  }/.`.|.....h..F/
	0x0620:  acfb 5642 cc51 4c94 d49a 7eea e3e8 ecb1  ..VB.QL...~.....
	0x0630:  3a41 5aa6 c4f3 c530 9417 c364 dbff 9711  :AZ....0...d....
	0x0640:  af15 e6f4 339d 5d8b 50a0 0814 5a6f ee6d  ....3.].P...Zo.m
	0x0650:  c791 e57f 5bbf 44a8 2bad 1417 e71f e2c9  ....[.D.+.......
	0x0660:  434a 1d72 64f5 3e6a cffc fc28 df85 6ee0  CJ.rd.>j...(..n.
	0x0670:  d0db e4f2 90af 56df b0f4 c710 6010 6a88  ......V.....`.j.
	0x0680:  1a37 8071 1ee5 14e5 6809 ce76 b297 a9a6  .7.q....h..v....
	0x0690:  920b d352 99a4 f069 e1bc f2c4 6a52 a4cd  ...R...i....jR..
	0x06a0:  3ca9 118a bd08 b715 e14b ce7c 9542 45ac  <........K.|.BE.
	0x06b0:  305c b1e1 d03f 4632 1372 576a 7582 3510  0\...?F2.rWju.5.
	0x06c0:  ef16 6b60 4878 7bb0 d1ae 6c56 de0c 8a11  ..k`Hx{...lV....
	0x06d0:  c58b e3d7 5554 6697 6243 fb01 8a71 23e7  ....UTf.bC...q#.
	0x06e0:  f385 81a9 cace 99ba 2e38 0234 7cea fc6f  .........8.4|..o
	0x06f0:  ec2b cfb4 6cef 6298 7bcd 3263 8ad7 8277  .+..l.b.{.2c...w
	0x0700:  79bb fbfc 596e 141f fe67 0491 6cce d963  y...Yn...g..l..c
	0x0710:  776e 6a78 f556 8aa3 b679 999d 2935 32e1  wnjx.V...y..)52.
	0x0720:  2b4f 540f 34ad 32d2 8560 a023 1557 1439  +OT.4.2..`.#.W.9
	0x0730:  2ee8 7f49 ad04 3565 7bdf c7c6 58d2 8599  ...I..5e{...X...
	0x0740:  201d 2760 917e 7904 56ae 8b1e 36fa 1696  ..'`.~y.V...6...
	0x0750:  dec8 362b d40e fe3c 9e7a e480 09f6 777f  ..6+...<.z....w.
	0x0760:  fe3e ca45 ea10 1b77 7929 ad6b 625e 4812  .>.E...wy).kb^H.
	0x0770:  e18b 7a6b 7755 d272 2d15 d21c b31b 040b  ..zkwU.r-.......
	0x0780:  0327 0df1 b224 1bee 1595 9b05 b2f2 ae89  .'...$..........
	0x0790:  907e 3dba f4e1 1539 de8a 7bde 9e5d 9a31  .~=....9..{..].1
	0x07a0:  e27b 2a9c 1747 4f83 d20f d8fd e9ea 58ac  .{*..GO.......X.
	0x07b0:  b987 7194 b8b3 1f60 0dbb 0795 4b61 afa3  ..q....`....Ka..
	0x07c0:  6cf1 bbef bbb9 21b3 71d2 8dbe 0795 b842  l.....!.q......B
	0x07d0:  bebe 7822 721b 6c01 be5e ba25 1860 bc3b  ..x"r.l..^.%.`.;
	0x07e0:  5a37 ba9d 1c73 499c 810c aa70 49c0 5499  Z7...sI....pI.T.
	0x07f0:  857b c24d 2c49 c1b3 7142 68aa 7a2f 3f6f  .{.M,I..qBh.z/?o
	0x0800:  3bfe 9f65 897c b98b 3b6f bb6e cafc b4bc  ;..e.|..;o.n....
	0x0810:  1b53 5b19 e96a 6cba ed7f 756f a733 bc6a  .S[..jl...uo.3.j
	0x0820:  f48c fcf7 2758 9a58 f700 202a 3958 d5d0  ....'X.X...*9X..
	0x0830:  3558 6e4a cb60 0490 d5f3 f789 9fb6 f0fc  5XnJ.`..........
	0x0840:  ad2e b415 db1a 22f4 84fc 7d68 134f db44  ......"...}h.O.D
	0x0850:  7b11 7218 0161 5e1e ef8c 744e fe5d ce5c  {.r..a^...tN.].\
	0x0860:  d7e6 715d 86b5 ed23 472d ea04 7a6d 842f  ..q]...#G-..zm./
	0x0870:  cd3f 83ac a846 3479 eae1 dfc5 b6f0 2af2  .?...F4y......*.
	0x0880:  1f46 7d2c 03fb 5364 4726 b05d b184 1361  .F},..SdG&.]...a
	0x0890:  cfe8 8fb8 39a3 ed17 6c47 d0ec a92e 8a1c  ....9...lG......
	0x08a0:  4471 f89c 5678 b017 2b25 f19e 8dc0 346c  Dq..Vx..+%....4l
	0x08b0:  23c8 dea9 77f3 4309 1ef7 a70c eb48 5671  #...w.C......HVq
	0x08c0:  235f 497b 7369 0ee5 c334 9e4f f828 f5f8  #_I{si...4.O.(..
	0x08d0:  c458 78fc 1ab4 3297 c0c7 2fbb 01cb 17a8  .Xx...2.../.....
	0x08e0:  fc87 bfcb b386 775d d2f3 8772 f3bd 667c  ......w]...r..f|
	0x08f0:  5e75 2448 98c8 7f97 633d 0ed0 18b1 92b9  ^u$H....c=......
	0x0900:  0ca0 cad1 51df 958c ae02 c552 64a9 35ad  ....Q......Rd.5.
	0x0910:  0b62 7ade 7534 fb1e 0280 a943 1a16 dfd8  .bz.u4.....C....
	0x0920:  2dae 191d b890 497a 7f2e a14b edad acc9  -.....Iz...K....
	0x0930:  0e64 3498 a30d bf20 36f2 71f9 456b 1361  .d4.....6.q.Ek.a
	0x0940:  dc5d aa57 f152 beef 7a0b 0dcd 69c5 f669  .].W.R..z...i..i
	0x0950:  6059 04f5 2bf9 c64c 60ab d96e 74b3 1c25  `Y..+..L`..nt..%
	0x0960:  6b30 9b07 f61d cad2 67de e7f3 971c 6047  k0......g.....`G
	0x0970:  d8c7 e88b 37d0 00eb f788 d936 b2fe 33cd  ....7......6..3.
	0x0980:  53cb 2b46 139f 07a9 f320 c47c d248 58ea  S.+F.......|.HX.
	0x0990:  d9ce a734 106f 56ee 59a5 81fd b090 3511  ...4.oV.Y.....5.
	0x09a0:  73ba 97dd 2ac2 d4d9 a294 a3e8 a6f7 3a96  s...*.........:.
	0x09b0:  a52b 9f78 5b3f 8fed b839 9a75 fedc dcbc  .+.x[?...9.u....
	0x09c0:  40e2 53f1 482e 76c9 7a13 9d95 202d b50e  @.S.H.v.z....-..
	0x09d0:  519d 8dc0 9092 5c9c 2e48 8ba3 4726 a5b0  Q.....\..H..G&..
	0x09e0:  1888 0463 49c5 b680 188c 1e73 a649 28b6  ...cI......s.I(.
	0x09f0:  ed0a 7ada 1120 ca3c cdea 15fb 2784 aafb  ..z....<....'...
	0x0a00:  322d d90a b829 50d9 2749 172a d50f 1e82  2-...)P.'I.*....
	0x0a10:  6bec e3cf 8514 fed4 6816 4310 f7c7 dc40  k.......h.C....@
	0x0a20:  353c 21b1 2674 bad5 a7c4 422a d290 0444  5<!.&t....B*...D
	0x0a30:  97d0 19fd 5406 1864 9769 3aa7 1266 8724  ....T..d.i:..f.$
	0x0a40:  2f31 62fc b011 8f2a a14c 46b3 c50d e7bf  /1b....*.LF.....
	0x0a50:  8a8b 93f4 da42 89d5 d4ab 046a 9500 9227  .....B.....j...'
	0x0a60:  f736 d2d1 a7b9 e401 0a54 e59b 00c0 6acf  .6.......T....j.
	0x0a70:  9a51 254e 73c3 3158 3d3d d710 d963 0319  .Q%Ns.1X==...c..
	0x0a80:  e3de 99a5 fb35 d5b1 b991 d114 e3ed 7afe  .....5........z.
	0x0a90:  3590 8d7a c5bd 85c3 4efb 5fd5 e0e8 32ae  5..z....N._...2.
	0x0aa0:  3b1c 493b af08 4ab4 3c00 8df5 87c3 6f0b  ;.I;..J.<.....o.
	0x0ab0:  1a24 4953 e347 b171 b9ec 9f55 9710 4912  .$IS.G.q...U..I.
	0x0ac0:  3dac be7a 6f14 080b 9774 4d3d 45b3 9489  =..zo....tM=E...
	0x0ad0:  db26 4c06 d01c 5525 d2df 7c69 336a 4fab  .&L...U%..|i3jO.
	0x0ae0:  317e 436e 5ec8 cdd0 2e42 7c30 40da 27f7  1~Cn^....B|0@.'.
	0x0af0:  729e 544a 48da 7a6a fdd6 388f 88b6 16d5  r.TJH.zj..8.....
	0x0b00:  6f74 3346 47f9 7a5a d4d1 40b8 799d 67e6  ot3FG.zZ..@.y.g.
	0x0b10:  9797 9461 04f4 dbe6 55e1 d218 58ba 54b2  ...a....U...X.T.
	0x0b20:  00b0 5bf4 158a 2062 db88 c878 9fc5 14f8  ..[....b...x....
	0x0b30:  4dcd 95ea 452b 209c 2d6f 70c5 f936 97b7  M...E+..-op..6..
	0x0b40:  bef4 ba31 5e62 0e1d a565 0f05 78e9 0eff  ...1^b...e..x...
	0x0b50:  45de dec9 14a8 ac52 1763 f661 251f 17c3  E......R.c.a%...
	0x0b60:  fec9 6126 25d4 034c dfe1 018d 9586 e48c  ..a&%..L........
	0x0b70:  3230 0439 7c30 b1e7 3102 9b98 b8df 4459  20.9|0..1.....DY
	0x0b80:  8b8d 8fc9                                ....
2024-02-12 22:30:50.325948 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [P.], seq 2897:3848, ack 518, win 506, options [nop,nop,TS val 3719012768 ecr 798483078], length 951
	0x0000:  4500 03eb c631 4000 3606 2d0b 0565 9676  E....1@.6.-..e.v
	0x0010:  ac19 05dc 01bb 8112 043c 8487 62a8 4e16  .........<..b.N.
	0x0020:  8018 01fa e4b9 0000 0101 080a ddab a1a0  ................
	0x0030:  2f97 e286 5eaa fa79 a386 5b11 7e6e 6816  /...^..y..[.~nh.
	0x0040:  7c51 3821 a3fe e2a7 45c1 4626 9133 d9be  |Q8!....E.F&.3..
	0x0050:  aa09 e407 e5b3 1a1d b712 d15e e83d b1ec  ...........^.=..
	0x0060:  4453 d4e1 4be5 370e f20e 1e6b f468 9285  DS..K.7....k.h..
	0x0070:  7964 9682 3278 b858 f680 032f 2057 d9a4  yd..2x.X.../.W..
	0x0080:  3c7b 5a6c 9905 6293 e5f5 426c 6616 2118  <{Zl..b...Blf.!.
	0x0090:  cf9c 77bf 3b87 f946 4110 1d8f de9d b105  ..w.;..FA.......
	0x00a0:  e1c2 3d43 a266 2595 041f d384 4fd2 bd6f  ..=C.f%.....O..o
	0x00b0:  3362 5bd6 582d 58b3 f24c 604d 19a8 e303  3b[.X-X..L`M....
	0x00c0:  a5fc 19f0 e050 dfb1 629a b7ee c410 c6f5  .....P..b.......
	0x00d0:  9509 8d7f eed4 3c6c 7f22 2711 a3c7 8cc4  ......<l."'.....
	0x00e0:  914d 1627 dfea 9b8d b25d e012 529e 9faa  .M.'.....]..R...
	0x00f0:  d8f7 c6ca a109 0579 525e a4fd 4c64 ec8a  .......yR^..Ld..
	0x0100:  6f3c 3beb 37b8 2096 fef2 a108 6ecb 52a7  o<;.7.......n.R.
	0x0110:  34f3 783e 036e 0b4b e029 667b a7f0 b153  4.x>.n.K.)f{...S
	0x0120:  0103 495f 7c71 9a93 bacd 2333 3aac ae8b  ..I_|q....#3:...
	0x0130:  b789 35de 96b8 9d78 ff94 29f4 85c6 9dd6  ..5....x..).....
	0x0140:  9395 d49a b470 ae14 ff8e 1f1f 8e6e f921  .....p.......n.!
	0x0150:  6a59 c450 212a 4823 6fe3 a22c 0a35 9f6c  jY.P!*H#o..,.5.l
	0x0160:  4da3 2d75 6f35 1868 18f6 2be6 75cb 5141  M.-uo5.h..+.u.QA
	0x0170:  37e3 7c3b d7d1 61ea 2d3c a59a cad9 196a  7.|;..a.-<.....j
	0x0180:  4bde 8798 c900 9667 ea3e a4de a729 b40b  K......g.>...)..
	0x0190:  82f0 addb 0577 5249 27fb 0190 55da 74ac  .....wRI'...U.t.
	0x01a0:  57a6 f3f1 95d7 e391 27e6 373a 1a54 808c  W.......'.7:.T..
	0x01b0:  06dd c115 01b9 917f 01c5 80cb e792 91ff  ................
	0x01c0:  c730 6ddd 63d6 c8dd 6e23 792e bf6f 924a  .0m.c...n#y..o.J
	0x01d0:  0e30 c01d 7285 439e 0990 4c2f eb32 88dc  .0..r.C...L/.2..
	0x01e0:  6a05 0c04 56c7 50cd 3a37 8d6d fb5d 31aa  j...V.P.:7.m.]1.
	0x01f0:  f905 c969 2f47 d644 8616 61a6 1ce1 4612  ...i/G.D..a...F.
	0x0200:  84ae e984 c059 8ce5 b7ad 34b2 5d4b 8b45  .....Y....4.]K.E
	0x0210:  85c4 7f2a 4971 859d de8f e902 d6f9 4002  ...*Iq........@.
	0x0220:  3b87 689a 87eb 6263 de21 a0c6 3041 0b8d  ;.h...bc.!..0A..
	0x0230:  8ff3 c11b 96fd 637a 9664 da67 b096 6c0f  ......cz.d.g..l.
	0x0240:  feca e291 41c0 f0c4 2ff9 f88b 44e8 af34  ....A.../...D..4
	0x0250:  0098 c24d e916 e0fd 1867 8580 26e0 1f55  ...M.....g..&..U
	0x0260:  5ed2 db96 34c5 2a99 2ebb 37e9 cefb 29c3  ^...4.*...7...).
	0x0270:  f29c 8036 b053 f02d 1d69 2afe 8701 c85b  ...6.S.-.i*....[
	0x0280:  1656 9975 871b db0e 5fe4 a898 e08b 1c93  .V.u...._.......
	0x0290:  1da2 12a7 deb0 33bd cce0 b0f5 adc0 6bec  ......3.......k.
	0x02a0:  03a3 b87e 73d1 ba6e d0d1 a902 fb70 7947  ...~s..n.....pyG
	0x02b0:  3466 0954 6f47 d0a0 5676 3667 7fc9 7e40  4f.ToG..Vv6g..~@
	0x02c0:  932d d1e4 e95a 1b87 a38d 979b 33fe 05de  .-...Z......3...
	0x02d0:  b95c 2216 de88 0eb3 b2e6 87a1 6d4b b2f6  .\".........mK..
	0x02e0:  2f86 9b3d 18c8 9e18 809b d4a5 8c66 8c94  /..=.........f..
	0x02f0:  e907 b48c 2f48 4cba 04f8 63dd e494 14ba  ..../HL...c.....
	0x0300:  25d8 2372 e4f4 9a06 5a9e 2a4e 9c4e bb00  %.#r....Z.*N.N..
	0x0310:  80bf b108 7c38 3a44 539d 9995 8cff f83d  ....|8:DS......=
	0x0320:  3049 923d c528 0657 cb36 d370 1703 0300  0I.=.(.W.6.p....
	0x0330:  8089 72cf 3d01 2a12 f475 f76d 7cbd 65cc  ..r.=.*..u.m|.e.
	0x0340:  e695 ea15 a64c 7413 d72d f615 cccb 95da  .....Lt..-......
	0x0350:  ddc2 9c27 649f 1dcd e9e3 0351 f7b9 5f36  ...'d......Q.._6
	0x0360:  1ab9 1e8d edb3 f0a9 3bab 9fa1 d5a0 fb80  ........;.......
	0x0370:  abcd 86d0 c0f5 d9ac 5542 8837 92aa ae0e  ........UB.7....
	0x0380:  ac31 5c95 7abd c3f4 8b3f b1f4 b5c5 d5be  .1\.z....?......
	0x0390:  aca9 4ad9 d549 7e8e 088c 54d9 4b07 4c7b  ..J..I~...T.K.L{
	0x03a0:  37e2 4533 e0d0 aa1a 4b34 cf09 3527 7174  7.E3....K4..5'qt
	0x03b0:  1917 0303 0035 cb43 21fb 85ad 724a e8f5  .....5.C!...rJ..
	0x03c0:  bd25 ae36 f6bd a894 9da8 b5ed 35fb c825  .%.6........5..%
	0x03d0:  5cb2 4c6a d676 3ca7 61d3 f3e3 2e07 2933  \.Lj.v<.a.....)3
	0x03e0:  dea6 2bfb f634 970d 4058 a8              ..+..4..@X.
2024-02-12 22:30:50.495204 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [P.], seq 3848:4006, ack 1156, win 502, options [nop,nop,TS val 3719012938 ecr 798483258], length 158
	0x0000:  4500 00d2 c632 4000 3606 3023 0565 9676  E....2@.6.0#.e.v
	0x0010:  ac19 05dc 01bb 8112 043c 883e 62a8 5094  .........<.>b.P.
	0x0020:  8018 01f6 4dd7 0000 0101 080a ddab a24a  ....M..........J
	0x0030:  2f97 e33a 1703 0300 4ad9 9ccc 652f ff1a  /..:....J...e/..
	0x0040:  8e25 becc 4529 16cf 7442 6a29 f3a1 f33d  .%..E)..tBj)...=
	0x0050:  cc39 4a3f de25 a40e 3dee 4dcf 7a43 3f1b  .9J?.%..=.M.zC?.
	0x0060:  8a29 3e27 59ce 527a 8181 3751 64c5 69bc  .)>'Y.Rz..7Qd.i.
	0x0070:  6a56 fdfe 2779 26c2 86b2 0202 8025 b61f  jV..'y&......%..
	0x0080:  320d 0c17 0303 004a 8f2c df68 b3cf ab22  2......J.,.h..."
	0x0090:  ee45 ca3a 7036 d6f5 e4ca 309e c660 4981  .E.:p6....0..`I.
	0x00a0:  7319 adf4 0346 f944 86d7 df3b da48 3a2a  s....F.D...;.H:*
	0x00b0:  8121 77a1 e614 4fe1 dfc4 f65f 2c9e 2f7d  .!w...O...._,./}
	0x00c0:  db21 5f63 fd13 eb81 8630 1ed9 b027 3627  .!_c.....0...'6'
	0x00d0:  6641                                     fA
2024-02-12 22:30:50.499620 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [P.], seq 4006:4281, ack 1156, win 502, options [nop,nop,TS val 3719012943 ecr 798483258], length 275
	0x0000:  4500 0147 c634 4000 3606 2fac 0565 9676  E..G.4@.6./..e.v
	0x0010:  ac19 05dc 01bb 8112 043c 88dc 62a8 5094  .........<..b.P.
	0x0020:  8018 01f6 45b3 0000 0101 080a ddab a24f  ....E..........O
	0x0030:  2f97 e33a 1703 0301 0edc 82d2 29d2 e501  /..:........)...
	0x0040:  11a1 ef6f 42ec 7053 cc81 149c 9d70 b82a  ...oB.pS.....p.*
	0x0050:  5ea3 09dc c664 7517 8a8e 12d0 0c1f 2459  ^....du.......$Y
	0x0060:  e562 fa64 cfa5 e0df b042 5f49 b933 2273  .b.d.....B_I.3"s
	0x0070:  a5fa c159 90d8 6d71 ab59 3ea2 8fbb 5435  ...Y..mq.Y>...T5
	0x0080:  b475 22e5 5991 d7ce c90b 55b7 be0e a7c4  .u".Y.....U.....
	0x0090:  488f 3b7c 0d34 3192 1594 c400 0ac9 ded8  H.;|.41.........
	0x00a0:  03a9 3253 a45f 4e60 76ed e66d fd4b 3aa8  ..2S._N`v..m.K:.
	0x00b0:  5f5a 4962 8eea f19f a26e 1cd8 4782 215f  _ZIb.....n..G.!_
	0x00c0:  9f4b cab2 1098 3f24 5019 930f 61b6 5a1f  .K....?$P...a.Z.
	0x00d0:  8e7e 3995 abeb 9a3c 1c3c 597e 9707 105a  .~9....<.<Y~...Z
	0x00e0:  13eb ded6 1d54 7f34 aa58 4dc3 e88f 8eab  .....T.4.XM.....
	0x00f0:  92c2 e44b b8ae 8cf1 7052 3164 d778 4cac  ...K....pR1d.xL.
	0x0100:  5c3e c8da 7b60 07ee 9fe9 18c4 b5cf a05f  \>..{`........._
	0x0110:  7ac1 5d38 0f26 6113 4ca1 a871 7379 b2ac  z.]8.&a.L..qsy..
	0x0120:  25f6 c4d6 e9b3 6960 d500 e116 d877 1f94  %.....i`.....w..
	0x0130:  2102 31c1 327b e5f8 7367 c22b 7c11 ea11  !.1.2{..sg.+|...
	0x0140:  eb60 ea3a f975 bf                        .`.:.u.
2024-02-12 22:30:55.501710 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [P.], seq 4281:4305, ack 1156, win 502, options [nop,nop,TS val 3719017945 ecr 798483420], length 24
	0x0000:  4500 004c c635 4000 3606 30a6 0565 9676  E..L.5@.6.0..e.v
	0x0010:  ac19 05dc 01bb 8112 043c 89ef 62a8 5094  .........<..b.P.
	0x0020:  8018 01f6 c7b0 0000 0101 080a ddab b5d9  ................
	0x0030:  2f97 e3dc 1703 0300 13c8 4d39 0e54 2714  /.........M9.T'.
	0x0040:  5c51 f47b 1a68 36d1 2dc5 73be            \Q.{.h6.-.s.
2024-02-12 22:30:55.501931 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [F.], seq 4305, ack 1156, win 502, options [nop,nop,TS val 3719017945 ecr 798483420], length 0
	0x0000:  4500 0034 c636 4000 3606 30bd 0565 9676  E..4.6@.6.0..e.v
	0x0010:  ac19 05dc 01bb 8112 043c 8a07 62a8 5094  .........<..b.P.
	0x0020:  8011 01f6 bbae 0000 0101 080a ddab b5d9  ................
	0x0030:  2f97 e3dc                                /...
2024-02-12 22:30:55.659048 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [.], ack 1156, win 502, options [nop,nop,TS val 3719018102 ecr 798483420,nop,nop,sack 1 {1180:1181}], length 0
	0x0000:  4500 0040 c637 4000 3606 30b0 0565 9676  E..@.7@.6.0..e.v
	0x0010:  ac19 05dc 01bb 8112 043c 8a08 62a8 5094  .........<..b.P.
	0x0020:  b010 01f6 1e50 0000 0101 080a ddab b676  .....P.........v
	0x0030:  2f97 e3dc 0101 050a 62a8 50ac 62a8 50ad  /.......b.P.b.P.
2024-02-12 22:30:55.659413 eth0  In  IP 5.101.150.118.443 > 172.25.5.220.33042: Flags [R], seq 71076335, win 0, length 0
	0x0000:  4500 0028 0000 4000 3606 f6ff 0565 9676  E..(..@.6....e.v
	0x0010:  ac19 05dc 01bb 8112 043c 89ef 0000 0000  .........<......
	0x0020:  5004 0000 5117 0000                      P...Q...
2024-02-12 22:31:14.670866 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [.], ack 4621, win 138, options [nop,nop,TS val 3229597294 ecr 1443997892], length 0
	0x0000:  4500 0034 49ac 4000 2206 60bb 8c52 7015  E..4I.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 701d 115a 2e2b  .......`..p..Z.+
	0x0020:  8010 008a 47a9 0000 0101 080a c07f be6e  ....G..........n
	0x0030:  5611 a8c4                                V...
2024-02-12 22:31:14.672404 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 2096:2144, ack 4621, win 138, options [nop,nop,TS val 3229597295 ecr 1443997892], length 48
	0x0000:  4500 0064 49ad 4000 2206 608a 8c52 7015  E..dI.@.".`..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 701d 115a 2e2b  .......`..p..Z.+
	0x0020:  8018 008a 6933 0000 0101 080a c07f be6f  ....i3.........o
	0x0030:  5611 a8c4 1703 0300 2bbc fd71 2dba af9a  V.......+..q-...
	0x0040:  2c9c 7b27 a311 8797 0f23 e6e2 8bfe d40a  ,.{'.....#......
	0x0050:  8254 6032 74fb 0ec7 b7b9 9a59 f9fd 5d0c  .T`2t......Y..].
	0x0060:  c517 c0bb                                ....
2024-02-12 22:31:14.677455 eth0  In  IP 140.82.112.21.443 > 172.25.5.220.34912: Flags [P.], seq 2144:2620, ack 4621, win 138, options [nop,nop,TS val 3229597300 ecr 1443997892], length 476
	0x0000:  4500 0210 49ae 4000 2206 5edd 8c52 7015  E...I.@.".^..Rp.
	0x0010:  ac19 05dc 01bb 8860 c8aa 704d 115a 2e2b  .......`..pM.Z.+
	0x0020:  8018 008a bbf9 0000 0101 080a c07f be74  ...............t
	0x0030:  5611 a8c4 1703 0301 d746 215e fa1f 187e  V........F!^...~
	0x0040:  07b6 aded 0098 4315 2da9 4aa5 cb0e f439  ......C.-.J....9
	0x0050:  3735 bd35 04f7 a8fe 5abf 94f3 997a 2446  75.5....Z....z$F
	0x0060:  b6dd a764 65ea 51d8 6a86 1b58 de32 e413  ...de.Q.j..X.2..
	0x0070:  d4a0 aae5 256f e4e4 58fd 84c8 ba5e cf64  ....%o..X....^.d
	0x0080:  c0cc 54ca cf30 35df 5658 056a f67e e3d5  ..T..05.VX.j.~..
	0x0090:  2f9d 17c2 7259 58a4 5f7c 8ea6 d922 6b9d  /...rYX._|..."k.
	0x00a0:  acce 0836 29e2 7696 c3d9 1d0a 413c 58b4  ...6).v.....A<X.
	0x00b0:  25c6 c452 8d12 b977 fc1f 544b d2fe 7807  %..R...w..TK..x.
	0x00c0:  2348 009a d5d0 3789 a67e 0422 9f08 2aeb  #H....7..~."..*.
	0x00d0:  dc66 46e5 81b9 3ae4 4e9f 2056 d95f 4619  .fF...:.N..V._F.
	0x00e0:  cb93 2568 faaa 7eb2 264d 10a7 d548 2938  ..%h..~.&M...H)8
	0x00f0:  8744 7de8 7221 9cae 8adb 86d0 7cf6 99d6  .D}.r!......|...
	0x0100:  931d 390c 4b20 b1f5 8f3d 85e0 a651 dc3d  ..9.K....=...Q.=
	0x0110:  a196 0e5e 4a5f eb44 49ac 1ec7 11dc c6a3  ...^J_.DI.......
	0x0120:  6db7 220d bee9 a5c5 a90c a6e5 9f1b 9bdc  m.".............
	0x0130:  4fdc c406 fe73 5d9a 4308 c2b7 a83b bf18  O....s].C....;..
	0x0140:  bfbd 9410 51f7 a43a ce0b ec4b 9150 f222  ....Q..:...K.P."
	0x0150:  4f0c 1f8b c794 aa71 3b4e fd5c 4e20 e183  O......q;N.\N...
	0x0160:  3b63 e5d2 b099 c9c9 1ed4 7afc 91e9 24e4  ;c........z...$.
	0x0170:  0e55 c417 548e 95d2 ff65 dd3b 4607 238b  .U..T....e.;F.#.
	0x0180:  a83f 2836 fc67 727a dc2d 4ae9 03c0 1bd3  .?(6.grz.-J.....
	0x0190:  c3d9 6ebe 34af 1e6d 00c1 e1c6 cbc1 f62e  ..n.4..m........
	0x01a0:  4300 c464 36fb 5524 a403 4675 2b73 6e8c  C..d6.U$..Fu+sn.
	0x01b0:  fb82 0a2a 4956 6786 0ca0 bc50 f7f8 63d3  ...*IVg....P..c.
	0x01c0:  a5f1 94f2 848c c268 2a11 2b1f 169a 026e  .......h*.+....n
	0x01d0:  1279 6ec6 233f 6b15 48e3 d3ac b9bf 0002  .yn.#?k.H.......
	0x01e0:  7ab2 5a6c c2e9 54f4 d038 ab59 9958 d51f  z.Zl..T..8.Y.X..
	0x01f0:  3a3d 18d8 82f2 46fe 9156 a1be bcf8 1057  :=....F..V.....W
	0x0200:  ae9c 0fa1 72e6 e493 97a6 4105 9f23 d1f9  ....r.....A..#..
```


## Roadmap
TBD 

## Authors and acknowledgment
Author: Joel Crouch

## License
MIT License

Copyright (c) 2024 Joel Crouch crouchj@pdx.edu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Project status
TBD