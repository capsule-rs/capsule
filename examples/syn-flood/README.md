# TCP SYN flood example

SYN flood is a form of denial-of-service attack in which the sender attempts to consume resources on the target host by sending large amount of SYN packets.

## Overview

SYN flood exploits the [TCP three-way handshake](https://tools.ietf.org/html/rfc793#section-3.4) by sending large amount of SYNs to the target with spoofed source IP addresses. The target will send SYN-ACK to these falsified IP addresses. They will either be unreachable or not respond.

This example demonstrates how to generate new packets instead of receiving packets from a port.

## Running the application

The example is located in the `examples/syn-flood` sub-directory. To run the application,

```bash
/examples/syn-flood$ cargo run -- -f syn-flood.toml
```

To observe the `SYN` flood traffic, in the vagrant VM, run `tcpdump` to capture packets sent to the destination IP address and port,

```bash
vagrant$ sudo tcpdump -i eth3 -nn host 10.100.1.254 and port 80

tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth3, link-type EN10MB (Ethernet), capture size 262144 bytes
18:59:27.140269 IP 136.178.185.105.0 > 10.100.1.254.80: Flags [S], seq 1, win 10, length 0
18:59:27.140275 IP 225.67.11.246.0 > 10.100.1.254.80: Flags [S], seq 1, win 10, length 0
18:59:27.140279 IP 12.164.180.121.0 > 10.100.1.254.80: Flags [S], seq 1, win 10, length 0
...
```

## Explanation

`cap0` is configured to transmit on lcore `0` with queue depth set at `2048`.

The example spawns a separate worker task on lcore `1` that will at 50ms interval generate a batch of 128 TCP SYN packets and send them through `cap0`. Each generated TCP SYN will have a random source IP address. The destination is set to `10.100.1.254` on port `80`, which is the address of the `eth3` interface on the host. (On a side note, the 50ms delay is necessary because emulated `virtio` driver is too slow on tx. Without a delay, the mempool is exhausted.)

```bash
vagrant$ ip addr show dev eth3

5: eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:00:00:ff:ff:ff brd ff:ff:ff:ff:ff:ff
    inet 10.100.1.254/24 brd 10.100.1.255 scope global eth3
       valid_lft forever preferred_lft forever
```

`ctrl-c` to stop the worker task and quit the application.
