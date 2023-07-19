# 🛡️ OpenVPN Application Filter Setup

Society is more prone to ddos attacks over 1M dollars in revenue is loss every minute from DDoS attacks. 

## 🌊 Understanding Socket Floods

A socket flood is a type of attack where the attacker attempts to establish an huge number of connections, thereby overwhelming the target's CPU.

![Socket Flood Image](https://github.com/SnoopWS/DDoS-Research/assets/123210023/3988130b-bfe3-4869-bea3-9ca0e98e852e.png)

## 🔍 Analyzing Socket Floods

### Identifying Features

Several key identifiers can help us identify packets involved in this specific socket flood attack:

- Flags: PSH and ACK (0x018)
- Header Length: 20 bytes (equivalent to 5 options)
- TCP Sequence Number: 1
- Urgent Pointer: 0

> 📌 Note: Timestamps are not used in this case. As `tcpdump` doesn't support timestamps, we will not consider them here.

We can follow the packets using `tcpdump` by making a simple expression:

```bash
tcpdump -i any 'tcp[13] == 24 and tcp[4:4] == 1 and tcp[12] / 16 == 5'
```

![tcpdump Image](https://github.com/SnoopWS/DDoS-Research/assets/123210023/d9a8162b-fc93-437c-a570-c3cbd619f01b.png)

## 🎖️ NBPF Compiler

To transform the `tcpdump's` bytecode into readable BPF (Berkeley Packet Filter) for iptables we can use the [NBPF compiler ↗](https://github.com/SnoopWS/nbpf-compiler). The NBPF compiler generates a cBPF (classic BPF) bytecode instead of regular BPF bytecode generated from tcpdump.

After compilation, we obtain the following bytecode:

> 17,48 0 0 0,84 0 0 240,21 0 13 64,48 0 0 9,21 0 11 6,40 0 0 6,69 9 0 8191,177 0 0 0,80 0 0 13,21 0 6 24,64 0 0 4,21 0 4 1,80 0 0 12,52 0 0 16,21 0 1 5,6 0 0 65535,6 0 0 0

![cBPF Image](https://github.com/SnoopWS/DDoS-Research/assets/123210023/9f96e681-0d03-404e-b9f4-63ef455d3370.png)

After inputing this bytecode into a iptable using the BPF module, we get the following rule:

> iptables -t raw -A PREROUTING -p tcp --dport {Porthere} -m bpf --bytecode "17,48 0 0 0,84 0 0 240,21 0 13 64,48 0 0 9,21 0 11 6,40 0 0 6,69 9 0 8191,177 0 0 0,80 0 0 13,21 0 6 24,64 0 0 4,21 0 4 1,80 0 0 12,52 0 0 16,21 0 1 5,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-name RatelimitPSHACKSockets--hashlimit-mode srcip --hashlimit-upto 10/min --hashlimit-burst 1 -j ACCEPT

Integrating this rule will filter your application from this specific attack. However, please note that it will not stop every socket method. To create a more secure application filter for OpenVPN and prevent DDoS attacks from affecting the application unless the port is saturated, we'll continue with additional configurations.

## 🧱 Application Filters

First, let's secure your server by whitelisting SSH to avoid being locked out:

```
iptables -A INPUT -p tcp -s x.x.x.x --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP
```

To keep this article concise, I have written three basic BPF rules that match the 20-byte headers and openvpn messages that allow all desktop platforms (Linux, Windows, macOS). Additionally, addiotnally there is another rule included that drops annoying SYN-based socket flood that tries to replicate Linux devices:

```
# Allow Windows
iptables-t raw -A PREROUTING -p tcp --dport 1194 -m bpf --byte "19,48 0 0 0,84 0 0 240,21 0 15 64,48 0 0 9,21 0 5 6,40 0 0 6,69 11 0 8191,177 0 0 0,72 0 0 20,21 7 6 56,21 0 7 17,40 0 0 6,69 5 0 8191,177 0 0 0,72 0 0 8,21 1 0 56,21 0 1 64,6 0 0 65535,6 0 0 0" -j ACCEPT
# Allow Linux / MacOS
iptables -t raw -A PREROUTING -p tcp --dport 1194 -m bpf --bytecode "12,177 0 0 0,72 0 0 20,21 7 6 56,21 0 7 17,40 0 0 20,69 5 0 8191,177 0 0 0,72 0 0 8,21 1 0 56,21 0 1 64,6 0 0 1,6 0 0 0" -j ACCEPT
# SYN-based socket flood
iptables -t raw -A PREROUTING -p tcp --dport 1194 -m bpf --bytecode "15,40 0 0 12,21 0 12 2048,48 0 0 23,21 0 10 6,40 0 0 20,69 8 0 8191,177 0 0 14,80 0 0 27,69 0 5 24,64 0 0 18,21 0 3 1,64 0 0 22,21 0 1 1,6 0 0 262144,6 0 0 0" -j DROP
```

Unfortunately, mobile devices do not have libpcap support. To account for this limitation, we'll add an exception in case the device is not supported by our BPF application filter:

```
# Only allow unrecognized devices 2 syn packets a minute.
iptables -t raw -A PREROUTING -p tcp --syn --dport 1194 -m hashlimit --hashlimit 2/minute --hashlimit-mode srcip --hashlimit-name syn_rate_limit -j ACCEPT
```

Now, let's only allow the first SYN packet to be registered via a SYN PROXY if the packet can't meet the conditions it will not complete the handshake and unable to establish a connection.:

```
# Synproxy all invalid/blocked connections
iptables -t raw -A PREROUTING -p tcp -m tcp --dport 1194 --syn -j CT --notrack
iptables -A INPUT -p tcp -m tcp --dport 1194 -m conntrack --ctstate INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -A INPUT -p tcp -m tcp --dport 1194 -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp --dport 1194 ! --syn -m conntrack --ctstate NEW -j DROP
iptables -t mangle -A PREROUTING -p tcp --dport 1194 -m conntrack --ctstate INVALID -j DROP
```
