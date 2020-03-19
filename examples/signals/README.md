# Linux signal handling example

An example demonstrating how to handle linux signals in a Capsule application.

## Running the application

The example is located in the `examples/signals` sub-directory. To run the application,

```
/examples/signals$ cargo run -- -f signals.toml
```

To send signals to the application, execute these commands in a separate terminal,

```
$ kill -s SIGHUP $(pidof signals)
$ kill -s SIGTERM $(pidof signals)
```

## Explanation

The `Runtime` exposes `SIGHUP`, `SIGINT`, and `SIGTERM` to the application. By default, any signal received will terminate the running application. To customize the signal handling, use `set_on_signal` to set a custom handler. A return of `false` will continue the runtime execution and a return of `true` will stop the application. This example will ignore `SIGHUP` and terminate on `SIGINT` (`Ctrl-C`) or `SIGTERM`.
