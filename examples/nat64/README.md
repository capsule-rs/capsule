# IPv6 to IPv4 network address translation example

**NAT64** is a network address translation gateway that facilitates communitcation between a host on an IPv6 network to another host on an IPv4 network. This example is a simplified implementation of such gateway that can forward TCP traffic between the two networks. Non-TCP or fragmented TCP packets are dropped by the gateway.

## Overview

A simple network topology may consist of a gateway with two interfaces connected to an IPv6 only network and an IPv4 only network, as illustrated by the following figure from [IETF RFC 6146](https://tools.ietf.org/html/rfc6146#section-1.2.2).

```
            +---------------------+         +---------------+
            |IPv6 network         |         |    IPv4       |
            |           |  +-------------+  |  network      |
            |           |--| Name server |--|               |
            |           |  | with DNS64  |  |  +----+       |
            |  +----+   |  +-------------+  |  | H2 |       |
            |  | H1 |---|         |         |  +----+       |
            |  +----+   |      +-------+    |  192.0.2.1    |
            |2001:db8::1|------| NAT64 |----|               |
            |           |      +-------+    |               |
            |           |         |         |               |
            +---------------------+         +---------------+
```

We will use the well-known prefix `64:ff9b::/96` as defined in [IETF RFC 6052](https://tools.ietf.org/html/rfc6052#section-2.1) to represent IPv4 addresses to the IPv6 network. Packets from the IPv6 network with a destination address within this prefix are routed to the **NAT64** gateway.

The gateway also has the address `203.0.113.1` assigned to it on the IPv4 network.

## Running the application

The example is located in the `examples/nat64` sub-directory. To run the application,

```
/examples/nat64$ cargo run -- -f nat64.toml
```

## Explanation

The **NAT64** gateway is configured with two ports. `eth1` is the port connected to the IPv6 network and `eth2` is the port connected to the IPv4 network. Also both ports are assigned the same core, core `1`.

```
[[ports]]
    name = "eth1"
    device = "0000:00:08.0"
    cores = [1]
    rxd = 512
    txd = 512

[[ports]]
    name = "eth2"
    device = "0000:00:09.0"
    cores = [1]
    rxd = 512
    txd = 512
```

Because they are assigned the same core, we can install a pipeline that forwards packets received on `eth1` through `eth2` by using `add_pipeline_to_core`.

### 6-to-4 translation

When the gateway receives an unfragmented IPv6 TCP packet, it will translate the destination address to the IPv4 counterpart by stripping away the `64:ff9b::/96` prefix. The source address will be replaced by the gateway's assigned IPv4 address and the source port will be replaced by a free port on the gateway. This address and port mapping is stored in the global `PORT_MAP`.

The IPv6 header is removed and replaced by an IPv4 header using the model outlined in [IETF RFC 6145](https://tools.ietf.org/html/rfc6145#section-5.1).

### 4-to-6 translation

When the gateway receives an unfragmented IPv4 TCP packet, it will translate the source address to the IPv6 counterpart by adding the `64:ff9b::/96` prefix. The TCP destination port is used as the lookup key to find the mapped destination address and port of the IPv6 host. This mapping is stored in the global `ADDR_MAP`.

The IPv4 header is removed and replaced by an IPv6 header using the model outlined in [IETF RFC 6145](https://tools.ietf.org/html/rfc6145#section-4.1).
