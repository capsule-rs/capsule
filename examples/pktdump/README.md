# Packet dump example

A simple example demonstrates pipeline combinators and packet peeking.

## Running the application

The example is located in the `examples/pktdump` sub-directory. To run the application,

```
/examples/pktdump$ cargo run -- -f pktdump.toml
```

## Explanation

Packet captures of IPv4 and IPv6 packets are played back with libpcap based virtual devices. The pipeline uses the `group_by` combinator to separate the packets to be processed by `dump_v4` and `dump_v6`. They both use `peek` instead of `parse` to read the packets immutability.
