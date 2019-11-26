# Kernel NIC interface example

The Kernel NIC Interface (KNI) is a DPDK control plane solution that allows userspace applications to exchange packets with the Linux kernel networking stack. See DPDK's [KNI documentation](https://doc.dpdk.org/guides/prog_guide/kernel_nic_interface.html) for more information. This example is a minimum program that can forward packets to and from the Linux kernel.

## Overview

KNI is useful for applications that want to conceptually share the port with the Linux kernel. For example, the application may want to leverage the kernel's built-in ability to handle [ARP](https://tools.ietf.org/html/rfc826) traffic instead of implementing the protocol natively. By enabling KNI for a port, a virtual device with the same name and MAC address as the port is exposed to the Linux kernel. The kernel will be able to receive all packets that are forwarded to this virtual device and the application will receive all packets the kernel sends to it.

## Running the application

The example is located in the `examples/kni` sub-directory. Before running the application, the DPDK KNI kernel module must be loaded,

```
$ insmod rte_kni.ko
```

To run the application,

```
/examples/kni$ cargo run -- -f kni.toml
```

While the application is running, the new virtual device is exposed to the kernel,

```
$ ip link

254: kni0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether ba:dc:af:eb:ee:f1 brd ff:ff:ff:ff:ff:ff
```

Kernel can assign an IP address to the device and bring the link up, at which point the kernel and the application can forward each other packets.

```
$ sudo ip addr add dev kni0 10.0.2.16/24
$ sudo ip link set up dev kni0
```

# Explanation

The assigned port `0000:00:08.0` has KNI support turned on by setting the `kni` flag to `true`. To forward packets received on the port to the kernel, the application adds a simple forwarding pipeline by calling `add_pipeline_to_port`. To forward packets received from the kernel through the port, the application adds another forwarding pipeline by calling `add_kni_rx_pipeline_to_port`.
