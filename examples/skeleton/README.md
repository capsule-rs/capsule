# Base skeleton example

The base skeleton example is the simplest Capsule application that can be written.

## Running the application

The example is located in the `examples/skeleton` sub-directory. To run the application,

```bash
/examples/skeleton$ cargo run -- -f skeleton.toml
```

## Explanation

`skeleton.toml` demonstrates the configuration file structure. The application must specify an `app_name`, `main_core`, `worker_cores`, `mempool`, and at least one `port`.

For the skeleton example, the main application thread, referred to as _lcore_ per DPDK terminology, runs on CPU physical core `0`. This main lcore executes the application bootstrapping logic, such as initializing the Capsule runtime. This example does not have any worker tasks, so `worker_cores` is set to empty.

The global mempool has a preallocated capacity of `65535` mbufs, or message buffers, with a `256` per lcore cache. The mempool's capacity places an upper bound on the total amount of memory used for storing network packets, and is constant for the lifetime of the Capsule application.

The example has one port configured, named `cap0`, using an in-memory ring-based virtual device. The port's receive loop, aka `rx`, is assigned to run on worker lcore `0`; and it's transmit loop, aka `tx`, is also assigned to run on worker lcore `0`. Both `rx` and `tx` are continuous loops constantly trying to receive and transmit network packets respectively. In practice, especially for heavy work load, they should be executed on separate, dedicated worker lcores for maximum throughput. Sharing the same worker lcore, like in this example, will have negative impact on performance because they are competing with each other for CPU time.

The `main` function first sets up the [`tracing`](https://github.com/tokio-rs/tracing) framework to record log output to the console at `DEBUG` level. Then it builds a `Runtime` with the settings from `skeleton.toml` and executes that runtime. Because there are no tasks scheduled with the runtime, the application doesn't do anything. It terminates immediately. The console output shows the lifecycle of the Capsule runtime from initialization to termination.
