# Ping4 daemon example

[Ping](http://manpages.ubuntu.com/manpages/bionic/man1/ping.1.html) is a utility used to test the reachability of a host. Ping4 daemon example is a small application that answers the ping requests.

## Running the application

The example is located in the `examples/ping4d` sub-directory. To run the application,

```
/examples/ping4d$ cargo run -- -f ping4d.toml
```

In a separate Vagrant VM terminal, first add a static entry to the ARP table so packets are routed to the interface `0000:00:08.0` for address `10.100.1.10`,

```
vagrant$ sudo arp -i eth3 -s 10.100.1.10 02:00:00:ff:ff:00
```

Check the ARP table to verify that the new entry is added,

```
vagrant$ sudo arp -an

? (10.100.1.10) at 02:00:00:ff:ff:00 [ether] PERM on eth3
```

Now while the application is still running, ping `10.100.1.10`,

```
vagrant$ ping -I eth3 10.100.1.10

PING 10.100.1.10 (10.100.1.10) from 10.100.1.255 eth3: 56(84) bytes of data.
64 bytes from 10.100.1.10: icmp_seq=1 ttl=255 time=3.96 ms
64 bytes from 10.100.1.10: icmp_seq=2 ttl=255 time=0.799 ms
64 bytes from 10.100.1.10: icmp_seq=3 ttl=255 time=0.525 ms
...
```

## Explanation

The `ping` utility sends out ICMPv4 echo request packets to address `10.100.1.10`. The packets are routed to the interface `0000:00:08.0` which the application is receiving from. For each echo request, the application generates and sends out an ICMPv4 echo reply packet in response. The `ping` utility calculates the latency as it receives each echo reply.
