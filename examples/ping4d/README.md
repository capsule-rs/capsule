# Ping4 daemon example

[Ping](http://manpages.ubuntu.com/manpages/bionic/man1/ping.1.html) is a utility used to test the reachability of a host. Ping4 daemon example is a small application that answers the ping requests.

## Running the application

The example is located in the `examples/ping4d` sub-directory. To run the application,

```bash
/examples/ping4d$ cargo run -- -f ping4d.toml
```

In a separate Vagrant VM terminal, first add a static entry to the ARP table so packets are routed to the interface `0000:00:08.0` for address `192.168.56.10`,

```bash
vagrant$ sudo ip neigh add 192.168.56.10 lladdr 02:00:c0:a8:38:0a dev eth3 nud permanent
```

Check the ARP table to verify that the new entry is added,

```bash
vagrant$ ip neigh show dev eth3

192.168.56.10 lladdr 02:00:c0:a8:38:0a PERMANENT
```

Now while the application is still running, ping `192.168.56.10`,

```bash
vagrant$ ping -I eth3 192.168.56.10

PING 192.168.56.10 (192.168.56.10) from 192.168.56.129 eth3: 56(84) bytes of data.
64 bytes from 192.168.56.10: icmp_seq=1 ttl=255 time=9.02 ms
64 bytes from 192.168.56.10: icmp_seq=2 ttl=255 time=3.79 ms
64 bytes from 192.168.56.10: icmp_seq=3 ttl=255 time=0.562 ms
...
```

## Explanation

`cap0` is configured to receive packets on lcore `0` and transmit packets on lcore `1`.

The `ping` utility sends out ICMPv4 echo request packets to address `192.168.56.10`. With the static ARP entry, the packets are routed to `cap0`. For each echo request, the application generates and sends out an ICMPv4 echo reply packet in response and drops the original echo request.

The `ping` utility calculates the latency as it receives each echo reply.

## Cleaning up

To clean up the ARP table,

```bash
vagrant$ sudo ip neigh del 192.168.56.10 dev eth3
```
