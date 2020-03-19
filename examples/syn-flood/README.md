# TCP SYN flood example

SYN flood is a form of denial-of-service attack in which the sender attempts to consume resources on the target host by sending large amount of SYN packets. This example demonstrates how to generate new packets as the start of a pipeline.

## Overview

SYN flood exploits the [TCP three-way handshake](https://tools.ietf.org/html/rfc793#section-3.4) by sending large amount of SYNs to the target with spoofed source IP addresses. The target will send SYN-ACK to these falsified IP addresses. They will either be unreachable or not respond.

## Running the application

The example is located in the `examples/syn-flood` sub-directory. To run the application,

```
/examples/syn-flood$ cargo run -- -f syn-flood.toml
```

## Explanation

The application schedules a periodic pipeline on port `eth1`'s assigned core `1`. The pipeline will repeat every 10 milliseconds. Instead of receiving packets from the port, the pipeline uses `batch::poll_fn` to generate a batch of new SYN packets each iteration and sends them through the port. Every packet is assigned a different spoofed source IP address.

On the main core `0`, a scheduled task prints out the port metrics once every second.

```
---
capsule:
  port:
    "dropped{port=\"eth1\",dir=\"tx\"}": 87545
    "errors{port=\"eth1\",dir=\"tx\"}": 0
    "octets{port=\"eth1\",dir=\"tx\",core=\"1\"}": 16008570
    "packets{port=\"eth1\",dir=\"tx\",core=\"1\"}": 296455
```
