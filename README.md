# IPv6 Scanning Project
This is an early-stage PhD project to investigate strategies which could be used to scan the IPv6 address space.

## Research Question
How would malware perform scans for automated host recruitment on IPv6-only networks?

## Why IPv6 Scans?
IPv4 address are 32-bits in length, giving a total of just under 4.3 billion possible addresses (2^32). This address space can be exhaustively scanned in several hours and is a relatively common practice for mass host recruitment.

The number of devices which require Internet connectivity has risen well beyond 4.3 billion, leading to compromises like Network Address Translation (NAT). These measures have created the appearance of a larger IPv4 address space, but they create other issues through breaking the end-to-end connection between devices. IPv6 addresses are intended to fix these issues by offering a much, much larger address space to allow each device to have its own unique address once again.

While a range of 2^128 possible addresses solves architectural problems caused by breaks in end-to-end connectivity between devices, it introduces a different problem: it's impossible to exhaustively scan an address space this vast in any useful timeframe. This is a potential problem for network administrators, who perform scans for legitimate purposes, but this will also affect the propagation of malware: many variants use exhaustive IPv4 scans for host recruitment in the wider Internet, and this will no longer be feasible in an IPv6 address space.

This project focuses on potential IPv6 scanning strategies from the perspective of malicious parties, rather than network administrators - there are interesting questions about how much data can be obtained about a host from its IPv6 address, and whether attacks might have an incentive to run IPv6 scans if this exposed information turns out to have an economic or opsec benefit for malware-as-a-service or pay-per-install operations.

## Completed Tasks 
* Completed Malware Unicorn RE 101 and 102
* BGPStream installed (minus kafka support - mint doesn't support a recent enough version (supports 0.8, requires 0.11), will set up on another machine later if kafka ends up being needed)
* Previous taxonomy and project notes obtained
* IPv6 address prefixes obtained and filtered for unique values (for a ~5 hour window in Aug 2014, will update to more recent values when tooling is complete)
* Overlaps between obtained prefixes found, chains between advertised prefixes documented
* Initial scanner script written - sends ICMPv6 Echo Request probe traffic to hosts, tracks traffic received from these hosts 
* Loss detection script started - rate-limiting behaviour can be detected through tracking ICMPv6 response rates

## Current Tasks
* Write a more detailed timeline of tasks in separate file
* Convert notes into a more polished writeup/progress report section
* Improve the organisation of obtained BGP data and graphs showing advertisement distribution - data exists, graphing scripts exist, but more detailed notes need to be taken about how graphs were obtained, labelling datasets, etc
* Look into variants of [ZeuS, a banking trojan said to have IPv6 capabilities for p2p networks](https://www.secureworks.com/research/the-lifecycle-of-peer-to-peer-gameover-zeus)
	* "Although CTU researchers have not yet observed active peers with IPv6 addresses, that scenario may change over time as more ISPs and commodity hardware support IPv6." - article published in 2012, need to find out if IPv6 is in use for p2p traffic - would be interesting to see how it manages host tracking/discovery and swarm management
	* articles from [2016](https://blog.radware.com/security/2016/12/ipv6-security-today/) and [????](https://www.sophos.com/en-us/security-news-trends/security-trends/why-switch-to-ipv6.aspx) indicate that IPv6 is in use for command and control traffic, but nothing mentioned about use of IPv6 scanning in samples
* Read Schindler et al. 2014 paper, [Shellcode Detection in IPv6 Networks with HoneydV6](https://www.scitepress.org/Papers/2014/50168/50168.pdf)
* Skim SANS Institute paper, [A Complete Guide on IPv6 Attack and Defense](https://www.sans.org/reading-room/whitepapers/detection/complete-guide-ipv6-attack-defense-33904)
* Do more work on [IPv6 local host discovery](https://twitter.com/noIPv6/status/1262233560204718080) - could help with locating hosts when searching by OUI doesn't work (ie. SLAAC not in use) or for more general target profiling
* Are SLAAC addresses accessible through active scanning even when privacy addresses are issued? (["yes and no!"](https://twitter.com/ArcStatic42/status/1262224894412099584))
* Look into when rate-limiting starts to occur on IPv6 networks - this will provide info on how long a scan would take to run per OUI on a target network

### tl;dr Scanner Responses
Note: the only probe traffic I have tested so far is ICMPv6 Echo Request
#### ICMPv6 Echo Request
* `Destination Unreachable: No Route`: network prefix is invalid/not in use
* `Destination Unreachable: Address Unreachable`: network prefix is live, but host interface identifier half of the IPv6 address is not currently allocated to a machine on this network
* `Echo Reply`: responsive, reachable IPv6 host
* `No response/timeout`: could be several things:
	* ICMPv6 traffic is getting dropped somewhere along the path: could be firewall rules at some entry point into the network ignore/drop ICMPv6 traffic instead of actively rejecting it
	* An active host: Windows 10 by default drops unsolicited ICMPv6 traffic, so if a timeout is an unusual response (ie. if most of the other responses received are `Address Unreachable`), it could be a sign of a windows 10 target
	* Rate-limiting: Some routers accept ICMPv6 traffic up to a certain threshold (eg. 6 packets per second), then drop any traffic received beyond that

## Current Questions
#### ie. smaller stuff which could maybe be another sub-project within the PhD
#### IPv6
* Which factors would encourage/force malware authors to use IPv6 scanning over IPv4 scans? Full migration to IPv6 will take decades and legacy use of IPv4 will likely continue, but additional data supplied by IPv6 addresses (eg. MAC addresses) and address persistence could provide new incentives.
* Can a SLAAC-assigned IID still be contacted even when a device has been given a privacy address (ie. is it a replacement for a SLAAC address or just an alias)?
	* ANSWER: many mainstream OSes seem to assign an ephemeral IPv6 privacy address alongside a privacy address which remains stable between reboots. The ephemeral address is used for outgoing traffic, but the stable privacy address is still responsive to incoming traffic if you can find it somehow.
* Which heuristics can be exploited for IPv6 scans on networks which do not assign SLAAC addresses (eg. are there any predictable patterns in RNG used to generate privacy addresses)? 
* Are any malware samples known to actually use IPv6 scanning in the wild?
* [Is it possible to maliciously deploy IPv6 to circumvent firewalls?](https://twitter.com/agowa338/status/1262246804768411653) Clients are said to prefer IPv6 to IPv4, this could allow a lot of interesting points of entry.
* How much work do malware authors actually have to put in to make use of IPv6 in their applications (and are they even aware their samples are using IPv6)? Reuse of existing application and library code is very common - if any of this is already IPv6-capable, this could reduce the barrier of entry to creating IPv6-enabled malware.
* How often do IPv6 scans get blocked by firewalls, given that IPv6 firewalls could be easily misconfigured or that traffic might not be routed through a local network router first?
* How long do IPv6 addresses live for? If they persist for a long time, IPv6 addresses potentially have market value - if not, there's much less incentive to run these scans.

## Potential Later Topics
#### ie. questions which are too large to cover in the PhD, but could be interesting work later on
* The economy of pay-per-install services: could MAC address info embedded in OUI-based IPv6 addresses provide a more bespoke service, given that specific models/brands of devices could be targeted by their IPv6 address?
* 'Malware authors probably wouldn't be able to write that': I keep hearing this anecdotally from several security researchers when asking about stuff like IPv6 and QUIC in malware. I'm not sure I buy it - if a group/lone actor is capable of finding new exploits, they clearly have enough technical skill to identify and implement something unusual. Most attacks go for the weakest link in the chain, but there are a number of questions I still have about more innovative stuff:
	* How widespread is the use of recycled code in malware samples (ie. does a new exploit tend to come from one party or are several people able to write these)? Mirai variants could be a good case study for this.
	* Which kinds of groups are more likely to develop and/or distribute novel malware functionality?
	* What proportion of clients of malware-as-a-service outfits have only minimal technical knowledge?
#### Phishing
* How do email addresses become available to actors running spam/phishing campaigns (ie. which sources are being crawled/mined)?
* What percentage of spam emails are about which topics in a given timeframe (finance, health, adult content, blackmail, etc)?
* Are there any geographical links between senders/recipients and subject matter(eg. certain things being more taboo/significant in certain countries)?
* How common is it for samples to try and appear legitimate to lure in as many users as possible compared to looking as suspicious as possible to mainly target vulnerable users? Do these approaches try to gain different things (credentials vs direct financial payments)?
* What's the best way to collect a wide range of spam/phishing campaign samples? Honeypot accounts and existing collectors for current campaigns, existing datasets for historical samples?

