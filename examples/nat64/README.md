# IPv6 to IPv4 network address translation example

**NAT64** is a network address translation gateway that facilitates communitcation between a client on an IPv6 network to a server on an IPv4 network. This example is a simplified implementation of such gateway that can forward TCP traffic between the two networks.

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

The example will not replicate the above network topology. Instead it will send to and receive from the same dual-stacked network interface `eth3`, and perform translations between the two stacks. Conceptually it will work the same way as a gateway for two single-stacked networks. Also, non-TCP or fragmented TCP packets are dropped.

To represent IPv4 addresses to the IPv6 network, the example uses the well-known prefix `64:ff9b::/96` as defined in [IETF RFC 6052](https://tools.ietf.org/html/rfc6052#section-2.1). For example, for the server listening on the address `10.100.1.254`, it's mapped IPv6 address is `64:ff9b::a64:1fe`.

The gateway also has the address `10.100.1.11` assigned to it on the IPv4 network.

## Running the application

The example is located in the `examples/nat64` sub-directory. To run the application,

```bash
/examples/nat64$ cargo run -- -f nat64.toml
```

In a separate Vagrant VM terminal, add a static entry to map the gateway's IPv4 address, `10.100.1.11`, to its link layer address on the IPv4 network,

```bash
vagrant$ sudo ip neigh add 10.100.1.11 lladdr 02:00:00:ff:ff:01 dev eth3 nud permanent
```

Also add a routing rule for the `64:ff9b::/96` subnet, and a static entry to map the server's IPv6 representation, `64:ff9b::a64:1fe`, to the gateway's link layer address on the IPv6 network.

```
vagrant$ sudo ip route add 64:ff9b::/96 dev eth3
vagrant$ sudo ip neigh add 64:ff9b::a64:1fe lladdr 02:00:00:ff:ff:00 dev eth3 nud permanent
```

Finally start a HTTP server on the IPv4 network, binding to its IP address `10.100.1.254`,

```bash
vagrant$ python3 -m http.server 8080 --bind 10.100.1.254

Serving HTTP on 10.100.1.254 port 8080 (http://10.100.1.254:8080/) ...
```

To test the gateway, `curl` the IPv6 representation of the server address,

```bash
vagrant$ curl -g -6 -v 'http://[64:ff9b::a64:1fe]:8080'

...
> GET / HTTP/1.1
> Host: [64:ff9b::a64:1fe]:8080
> User-Agent: curl/7.64.0
> Accept: */*
>
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Server: SimpleHTTP/0.6 Python/3.7.3
< Date: Sun, 28 Mar 2021 17:47:08 GMT
< Content-type: text/html; charset=utf-8
< Content-Length: 956
...
```

## Explanation

The gateway example is configured with two ports. Conceptually, `cap0` is the port on the IPv6 network receiving packets intended for the `64:ff9b::/96` subnet. `cap1` is the port on the IPv4 network with the address `10.100.1.11`.

### 6-to-4 translation

The interaction starts with a client, the `curl` program, on the IPv6 network tries to connect to a python HTTP server on the IPv4 network. When `cap0` receives the TCP packet, it will translate the destination address to the IPv4 counterpart by stripping away the `64:ff9b::/96` prefix. The source address will be replaced by the gateway's IPv4 address `10.100.1.11`, and the source port will be replaced by a free port on the gateway. The original source address and port are saved and will be used later to translate the response packets.

The IPv6 header is removed and replaced by an IPv4 header using the steps outlined in [IETF RFC 6145](https://tools.ietf.org/html/rfc6145#section-5.1).

Once the translation is complete, the packet is transmitted through `cap1` and routed to the python HTTP server.

### 4-to-6 translation

The response from the python HTTP server is routed to the gateway's IPv4 address because from the server's perspective, the request was originated from `10.100.1.11`, as shown in the access log.

```
10.100.1.11 - - [28/Mar/2021 17:47:08] "GET / HTTP/1.1" 200 -
```

The response TCP packets are received by `cap1`. It will translate the source address to the IPv6 counterpart by adding the `64:ff9b::/96` prefix. A lookup is performed with the TCP destination port to retrieve the source address and port of the original client on the IPv6 network.

The IPv4 header is removed and replaced by an IPv6 header using the steps outlined in [IETF RFC 6145](https://tools.ietf.org/html/rfc6145#section-4.1).

Once the translation is complete, the packet is transmitted through `cap0` and routed to the client.

A HTTP request-response cycle consists of multiple TCP packets, from connection establishment to termination. The entire TCP lifecycle is logged by the example application. `curl` writes out the response text after the process completes.

## Cleaning up

To clean up the static routes,

```bash
vagrant$ sudo ip neigh del 10.100.1.11 dev eth3
vagrant$ sudo ip neigh del 64:ff9b::a64:1fe dev eth3
vagrant$ sudo ip route del 64:ff9b::/96 dev eth3
```
