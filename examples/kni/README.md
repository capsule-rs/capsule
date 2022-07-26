# Kernel NIC interface example

The Kernel NIC Interface (KNI) is a DPDK control plane solution that allows userspace applications to exchange packets with the Linux kernel networking stack. See DPDK's [KNI documentation](https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html) for more information.

## Overview

KNI is useful for Capsule applications that want to delegate the processing of various network control plane protocols to either the Linux kernel or other implementations that run on Linux. For example, [Address Resolution Protocol](https://tools.ietf.org/html/rfc826) is the mechanism for hosts to discover each other's link layer address on an IPv4 network. Typically, the Linux kernel handles the ARP discovery for all the network interfaces on the host. However, because Capsule-bound network devices are not visible to the kernel, each Capsule application needs its own ARP implementation, otherwise the network won't be able to route packets to it. Or alternatively, an easier approach is for the application to simply leverage the kernel stack implementation by delegating and forwarding ARP packets via KNI.

This example demonstrates said approach by delegating the processing of [Neighbor Discovery Procotol](https://tools.ietf.org/html/rfc4861), the IPv6 equivalent of ARP, to the Linux kernel.

## Prerequisite

This application requires the kernel module `rte_kni`. Kernel modules are version specific. If you are using our Vagrant with Docker setup, the module is already preloaded. Otherwise, you will have to compile it by installing the kernel headers or sources required to build kernel modules on your system, then [build `DPDK` from source](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html).

Once the build is complete, load the module with command:

```bash
$ sudo insmod /lib/modules/`uname -r`/extra/dpdk/rte_kni.ko carrier=on
```

We may provide precompiled modules for different kernel versions and Linux distributions in the future. 

## Running the application

The example is located in the `examples/kni` sub-directory. To run the application,

```bash
/examples/kni$ cargo run -- -f kni.toml
```

While the application is running, in a seperate Vagrant VM terminal, check that a new virtual device `kni0` is exposed to the kernel,

```bash
vagrant$ ip link show dev kni0

14: kni0: <BROADCAST,MULTICAST> mtu 2034 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether 6a:80:63:c3:01:42 brd ff:ff:ff:ff:ff:ff
```

Change the MAC address of `kni0` to match the MAC address of the physical interface first; then bring up the link,

```bash
vagrant$ sudo ip link set dev kni0 address 02:00:00:ff:ff:00
vagrant$ sudo ip link set dev kni0 up
```

Once `kni0` is up, it should be automatically assigned an IPv6 address, we will need this address for the next step,

```bash
vagrant$ ip addr show dev kni0

14: kni0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 2034 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:00:00:ff:ff:00 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::ff:feff:ff00/64 scope link
       valid_lft forever preferred_lft forever
```

Finally use `socat` to read from `stdin`, and send the input messages as UDP packets to this IPv6 address. These packets will be routed to the running Capsule application,

```bash
vagrant$ socat -d -d -u - udp6:[fe80::ff:feff:ff00%eth3]:6667

Hello?
Is there anybody in there?
```

The running application should print out,

```
Mar 28 19:59:34.805  INFO kni: to kni0: Neighbor Solicitation
Mar 28 19:59:34.810  INFO kni: from kni0: Neighbor Advertisement
Mar 28 19:59:34.811  INFO kni: you said: Hello?

Mar 28 19:59:39.475  INFO kni: you said: Is there anybody in there?

```

# Explanation

Capsule leverages the KNI poll mode driver instead of the `librte_kni` API directly. This lets the application to interact with KNI the same way as any other physical or virtual port device.

The example is configured with one PCI port, `cap0`, and one KNI port, `kni0`. As new packets arrive through `cap0`'s rx, the application will forward all ICMPv6 packets to the `kni0`'s tx. For the sake of simplicity, it is assumed that all ICMPv6 packets received in this example will be NDP messages, and the application is delegating this link layer address discovery process to the kernel stack. In the reverse direction, kernel stack's NDP responses will come in through `kni0`'s rx, and immediately forwarded out through `cap0`'s tx without modifications. Because we assigned `cap0`'s link layer MAC address, `02:00:00:ff:ff:00`, to `kni0` with the `ip link set` command, the NDP responses already contain the correct link layer information.

When `socat` sends out an UDP packet via `eth3` to `kni0`'s IPv6 address `fe80::ff:feff:ff00`, a lookup is performed trying to find the link layer address of the destination. On the very first attempt, that link layer address is not found through the lookup. A neighbor solicitation message is broadcasted instead to initiate the discovery process.

`cap0` receives the broadcasted neighbor solicitation message and forwards it to the kernel stack via `kni0`. Kernel responds with a neighbor advertisement message because the IPv6 address matches the address of the `kni0` interface. This response is sent back to `eth3` through `kni0`'s rx then `cap0`'s tx, completing the discovery.

The link layer address from the response is cached, all UDP packets are routed to `cap0` with this lookup until the cached entry expires. The Capsule application will receive the UDP packets from `socat`. It parses and prints out the data payload.
