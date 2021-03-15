# Base skeleton example

The base skeleton example is the simplest Capsule application that can be written.

## Running the application

The example is located in the `examples/skeleton` sub-directory. To run the application,

```
/examples/skeleton$ cargo run -- -f skeleton.toml
```

## Explanation

`skeleton.toml` demonstrates the configuration file structure. The application must specify an `app_name`, `main_core`, `mempool`, and at least one `port`. For the skeleton example, the main application thread runs on CPU core `0`. It has a mempool with capacity of `65535` mbufs preallocated. It has one port configured to also run on CPU core `0`, using an in-memory ring-based virtual device.

The `main` function first sets up the [`tracing`](https://github.com/tokio-rs/tracing) framework to record log output to the console at `TRACE` level. Then it builds a `Runtime` with the settings from `skeleton.toml` and executes that runtime. Because there are no pipelines or tasks scheduled with the runtime, the application doesn't do anything. It terminates immediately.
