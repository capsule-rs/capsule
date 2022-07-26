# Packet dump example

An example demonstrating basic packet processing.

## Running the application

The example is located in the `examples/pktdump` sub-directory. To run the application,

```bash
/examples/pktdump$ cargo run -- -f pktdump.toml
```

## Explanation

Packet captures, or pcaps, of IPv4 and IPv6 TCP packets are played back with ports using `libpcap` based virtual devices. `cap0` replays the IPv4 pcap and `cap1` replays the IPv6 pcap. Both ports are receiving on the same worker lcore, and have transmit disabled.

The parse functions showcase the packet type system. Both IPv4 and IPv6 packet types are preceded by the Ethernet packet type. TCP packet type can succeed either IPv4 or IPv6 packet types.

Packets are dropped at the end of `dump_pkt`.

`ctrl-c` terminates the application.
