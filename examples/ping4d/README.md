# Ping4 daemon example

[Ping](http://manpages.ubuntu.com/manpages/bionic/man1/ping.1.html) is a utility used to test the reachability of a host. Ping4 daemon example is a small application that answers the ping requests.

## Running the application

The example is located in the `examples/ping4d` sub-directory. To run the application,

```
/examples/ping4d$ cargo run -- -f ping4d.toml
```

## Explanation

Ping operates by sending an ICMP echo request packet to the target host and waiting for an ICMP echo reply. The pipeline uses the `replace` combinator to create a new reply packet for each received request packet. The request packet is immutable.
