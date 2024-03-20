# Your Dog Barks all the time!
##   BAD NEIGHBOR : CVE-2020-16898
CVE-2020-16898 is a remote code execution vulnerability that exists within the Windows/TCP/IP stack. It is caused by ICMPV6 Router advertisement packets being improperly handled. An adversary may exploit this and possibly gain the ability to execute malicious code on the server or client. Malicious code that is being executed is in kernel space, so Microsoft and the Nations Security Vulnerability Database (nvd) has given this exploit a severity rating of 8.8. (severe) The exploit is known colloquially as 'Bad Neighbor'. 
### Targets of Bad Neighbor
The following builds are targets of Bad Neighbor:
Desktop Windows:
microsoft:windows:10:1709, :microsoft:windows_10:1803, :microsoft:windows_10:1903,
:microsoft:windows_10:1909, :microsoft:windows_10:2004
Microsoft Server:
microsoft:windows_server_2016:1903, microsoft:windows_server_2016:1909,
microsoft:windows_server_2016:2004, and microsoft:windows_server_2019:-:

If you upgrade to windows 11 on desktop, and as needed to Windows Server 11,  you can mitigate this vulnerability.  That is assuming this vulnerability is not available in the upgrades.

###  How doest it gain access?
Bad neighbor is essentially a buffer overflow attack.  Basically there is an option within ICMPv6 Router advertisments packets named "Recursive DNS server Option" (RDNSS).  There are several fields within it:  type, length, reserved, lifetime, and addresses of IPv6 recursive DNS servers.  When using the length field, it should be an odd value of at least length 3, because the length is counted in 8 byte pieces.  If there is an even value for length, it can be exploited.  
So...go on. Right lets be a little more specific.

The Length field specifies the length of the entire RDNSS option in bytes, including all its fields such as Type, Length, Reserved, Lifetime, and Addresses of IPv6 Recursive DNS Servers.  According to RFC 8106, the length is counted in increments of 8 bytes. So, for example, if the Length field has a value of 3, it implies that the total length of the RDNSS option should be 3 * 8 = 24 bytes. The last field of the RDNSS option contains the addresses of IPv6 Recursive DNS Servers. This field can contain a variable number of IPv6 addresses, each of which is 16 bytes long. The number of IPv6 addresses is not directly related to the Length field. 

Odd Length Requirement!: The vulnerability arises when an even length value is provided for the Length field. As per RFC 8106, the Length field should be an odd value of at least 3. This requirement ensures proper alignment and handling of the RDNSS option.   

In summary, the Length field in the RDNSS option specifies the total length of the option in bytes, including all its fields and IPv6 addresses. It  makes sure of  proper formatting and interpretation of the RDNSS option within the IPv6 Router Advertisement packet.  

### Router advertisement Packet Stuff

RFC 4861 (https://www.rfc-editor.org/rfc/rfc4861.html) shows the router advertisement type is 134, and we can probably use that data in our suricata rule to filter out the 'bad neighbor' attempts.

### Suricata rule for dealing with Bad Neighbor

Bad neighbor's most telling signature for the  is an even-length RDNSS option within an ICMPv6 Router Advertisement (RA) packet.   To mitigate it, a suricata rule would have to check the RDNSS option and insure it is odd.  So lets use this example and work back from it: 

```
suricata rule
 drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:”ET TROJAN Likely Bot Nick in IRC (USA +..)”; flow:established,to_server; flowbits:isset,is_proto_irc; content:”NICK “; pcre:”/NICK .*USA.*[0-9]{3,}/i”; reference:url,doc.emergingthreats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2;)

```

Ok.  So we want our suricata rule to reject or drop the packet, and we want protocol to be icmpv6 router advertisments.  So somehow we want to incorporate type 134 (rfc4891) and this data from the types in suricata (https://docs.suricata.io/en/suricata-5.0.3/rules/header-keywords.html#icmp-keywords), where # 9 is the router advertisements. These filters will narrow the packets down to possible attacks, and then we can check the length of the RDNSS option and make sure it is odd!

Here is an attempt: 
```
suricata rule
alert  any any -> any any (msg:"Possible Bad Neighbor Vulnerability Detected - Even Length RDNSS"; 
  icmp6_type:134; 
  content:"|01 25|"; distance: 1; within: 2; 
  content:"|xx & 01|"; distance: 1; within: 1;  
  sid:10001; rev:1;
)
```

That looks pretty promising.  Lets walk through it:  
action: alert   The action this rule provides is an alert.  We probably want a rejection.  Back to the docs!  Per the docs, a reject will also alert. Change that to 'reject'.

protocol: any. We could probably be a little more precise and make the protocol relevant to IPv6. Lets find out.  To the docs!  We can probably just use 'icmp' as our protocol filter, but what happens if there are nested protocols?  Let's keep it simple. 'any' it is.

src port -> dst port  For this option we have any src and any port to any destination and port.
We can return to this.

msg:msg:"Possible Bad Neighbor Vulnerability Detected - Even Length RDNSS"  This is a fine descriptive message for our imaginary log file.

This guy 'icmp6_type:134;' filters on the router advertisement. (see above)   Lets add this in too: 'itype:9'. It probably does the same filtering, so why not use two hammers instead of one?  Broken fingers?  

ADD reference and classtype?

##### More stuff from RFC 4861
The line 'content:"|01 25|"; distance: 1; within: 2;' is kinda found from reading more about rfc 4861, which seems to be where the adversary spent alot of time.  So here we are.  This line looks for two bit '01 and 25'.  The content:"|01 25|"; distance: 1; within: 2; line in the Surricata rule searches for two consecutive bytes, 01 and 25, within the packet payload. However, the distance and within parameters further refine the search location. Here's a breakdown of their roles:
content:"|01 25|": This part defines the literal byte sequence to search for (01 followed by 25 in hexadecimal).distance: 1: This parameter specifies the distance relative to the current search position where the pattern (|01 25|) should be located.
Content checks can be chained together. The distance helps define the offset from the previous check's location.
Here, distance: 1 indicates that the pattern (|01 25|) should be found one byte after the current search position. This likely refers to the position set by a preceding content check in the rule (not explicitly shown in the provided snippet).
within: 2: This parameter defines the range within which the pattern search should occur.


Final line!  'content:"|xx & 01|"; distance: 1; within: 1'  WHAT IN TARNATION? So here xx represents any two hexadecimal digits, & is the bitwise AND operation, and 01 is a hex value (1).   ASsuming the previous rules foound the RDNSS Options (25)  and used the 134 and 9 properly, you are in the right place.  Here's a little bit more explanation.  The option length in the RDNSS option specifies the total length for the option data (bytes).  The evne check looks at the least sighnificant bit(LSB), of the option length value. The goal of the rule is to id the even length options.  Doing a bitwise AND op with 01 isolates the LSB of the option length byte.  If he option length has an even value the LSB will be 0. Voila!

Asn the 'sid:100000001; rev:1;' are just essentially housekeeping.
    

    

Final suricata rule:
```
suricata rule
reject any any -> any any (msg:"Possible Bad Neighbor Vulnerability Detected - Even Length RDNSS"; 
  icmp6_type:134; 
  itype: 9;
  content:"|01 25|"; distance: 1; within: 2; 
  content:"|xx & 01|"; distance: 1; within: 1;  
  sid:100000001; rev:1;
)



```

###  BUT WAIT...LOOK what i found

This the actual method that works.  Lets see what it does.
https://github.com/advanced-threat-research/CVE-2020-16898

Here is the McAffee Method. This is the rule:

```
suricata
alert icmp any any -> any any (msg:"Potential CVE-2020-16898 Exploit"; lua:cve-2020-16898.lua; sid:202016898; rev:1;)

```

Looks pretty simple.  It checks protocol = 'icmp' as i suggest maybe doing for my little rule and then references a lua script. Lets look at that:

```
lua
function init(args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

function match(args)
    local packet = args["packet"]
    if packet == nil then
        print("Packet buffer empty! Aborting...")
        return 0
    end

    -- SCPacketPayload starts at byte 5 of the ICMPv6 header, so we use the packet buffer instead.
    local buffer = SCPacketPayload()
    local search_str = string.sub(buffer, 1, 8)
    local s, _ = string.find(packet, search_str, 1, true)
    local offset = s - 4

    -- Only inspect Router Advertisement (Type = 134) ICMPv6 packets.
    local type = tonumber(packet:byte(offset))
    if type ~= 134 then
        return 0
    end

    -- ICMPv6 Options start at byte 17 of the ICMPv6 payload.
    offset = offset + 16

    -- Continue looking for Options until we've run out of packet bytes.
    while offset < string.len(packet) do

        -- We're only interested in RDNSS Options (Type = 25).
        local option_type = tonumber(packet:byte(offset))

        -- The Option's Length field counts in 8-byte increments, so Length = 2 means the Option is 16 bytes long.
        offset = offset + 1
        local length = tonumber(packet:byte(offset))

        -- The vulnerability is exercised when an even length value is in an RDNSS Option.
        if option_type == 25 and length > 3 and (length % 2) == 0 then
            return 1

        -- Otherwise, move to the start of the next Option, if present.
        else
            offset = offset + (length * 8) - 1
        end
    end

    return 0
end
```

init :
Defines a table named needs.
Sets the value for the key "packet" in the needs table to the string "true". This likely indicates that the script requires a packet buffer as input,and returns the needs table.

OK. So init sets it up, and then function match does the heavy lifting.
function_match:
This function takes the needs table as an input, and if the packet does not exist there, quits.

SCPacketPayload probably retrieves the packet payload from somewhere and puts it into the variable 'buffer'.
search_str is the first 8 bytes from the 'buffer'.  
Use string.find to search for search_str inside the packet data, starting at offset ==1, and the store the starting position(s).

Does some calculation to get to a relevant data within the packet structure(-4.)

Extracts the byte value at the calculated offset and make it a number using 'tonumber'.
If the type is not equal to 134, return 0.  Great.
Sets a new offset value by adding 16 to the previous offset. This likely positions the script to start examining the ICMPv6 options section within the packet.
Enters a loop that continues as long as the offset is within the packet's length:
Extracts the option type by converting the byte value at the current offset to a number using tonumber.
Checks if the option type is equal to 25 (which corresponds to the RDNSS option).
Extracts the option length by converting the byte value at the offset after the option type to a number using tonumber. The script assumes the length is specified in units of 8 bytes.
Checks if the option type is 25, the length is greater than 3 bytes, and the length is even (using the modulo operator %):
If all conditions are met, the script returns 1, indicating a potential vulnerability (even length RDNSS option).

Otherwise, the script calculates a new offset by adding the option length multiplied by 8 (accounting for the 8-byte increments) and subtracting 1. This likely positions the script to examine the next option (if present).
If the loop finishes without finding a matching even-length RDNSS option, the function returns 0 (no match).

In general, the script analyzes ICMPv6 packets, specifically focusing on Router Advertisements (type 134). It gets relevant data from the packet payload and searches for the presence of an RDNSS option (type 25) with an even length. Even-length RDNSS options are  a signature of the "Bad Neighbor" exploit, and the script identifies such packets as potential vulnerabilities.

### Compare and contrast with my lil ding dong rule. 

Hmm. Well.  I think mine will work. In the absence of testing (TBD and TBT), lets call mine a good start.  It checks options 134 and 25 which we can use as filters for the router advertisements.  I am not sure if the bitwise operation will work. I will attempt to make a scapy test suite soon and update this.  The lua script seems to be a little more precise in parsing and getting to the right data. 
