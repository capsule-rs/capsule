# Capsule

A framework for network function development. Written in Rust, inspired by [NetBricks](https://www.usenix.org/system/files/conference/osdi16/osdi16-panda.pdf) and built on Intel's [Data Plane Development Kit](https://www.dpdk.org/).

## Table of Contents

* [Overview](#overview)
* [Quick Start](#quick-start)
* [Contributing](#contributing)
* [Code of Conduct](#code-of-conduct)
* [Contact](#contact)
* [Maintainers](#maintainers)
* [License](#license)

## Overview

The goal of `Capsule` is to offer an ergonomic framework for network function development that traditionally has high barriers of entry for engineers. We are building a tool to efficiently manipulate network packets while being type-safe, memory-safe, and thread-safe. By marrying `DPDK` with `Rust` Programming Language, `Capsule` offers

* a fast packet processor that uses minimum number of CPU cycles.
* a rich packet type system that guarantees memory-safety and thread-safety.
* a concise framework that makes complex applications easy to write.

## Quick Start

The easiest way to get started developing `Capsule` applications is to use the `Vagrant` [virtual machine](https://github.com/capsule-rs/sandbox/blob/master/Vagrantfile) and the `Docker` [sandbox](https://hub.docker.com/repository/docker/getcapsule/sandbox) we provide. The sandbox is preconfigured with all the necessary tools and libraries for `Capsule` development.

* [`DPDK` 18.11](https://doc.dpdk.org/guides-18.11/rel_notes/release_18_11.html)
* [`Clang`](https://clang.llvm.org/) and [`LLVM`](https://www.llvm.org/)
* [`Rust` 1.42](https://blog.rust-lang.org/2020/03/12/Rust-1.42.html)
* [`rr`](https://rr-project.org/) 5.3

You need to first install [`Vagrant`](https://www.vagrantup.com/) and [`VirtualBox`](https://www.virtualbox.org/) on your system. And install the following `Vagrant` plugins,

```
host$ vagrant plugin install vagrant-reload vagrant-disksize vagrant-vbguest
```

Then you can clone the sandbox repository, start and ssh into the vagrant VM,

```
host$ git clone https://github.com/capsule-rs/sandbox.git
host$ cd sandbox
host$ vagrant up
host$ vagrant ssh
```

Once you are inside the `Debian` VM with `Docker` installed. You can run the sandbox with the command,

```
vagrant$ docker run -it --rm \
    --privileged \
    --network=host \
    --name sandbox \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -v /lib/modules:/lib/modules \
    -v /dev/hugepages:/dev/hugepages \
    getcapsule/sandbox:18.11.6-1.42 /bin/bash
```

Make sure that you mount the working directory of your project as a volume for the sandbox. Then you can use `Cargo` commands inside the container as normal.

Add `Capsule` as a dependency to your `Cargo.toml` and you can start writing your application,

```toml
[dependencies]
capsule = "0.1"
```

See further [instructions](https://github.com/capsule-rs/sandbox/blob/master/README.md) if you want to develop `Capsule` without using either `Vagrant` or `Docker`.

## Contributing

Thanks for your help improving the project! We have a [contributing guide](https://github.com/capsule-rs/capsule/blob/master/CONTRIBUTING.md) to help you get involved with the `Capsule` project.

## Code of Conduct

This project and everyone participating in it are governed by the [Capsule Code Of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to this Code. Please report any violations to the code of conduct to capsule-dev@googlegroups.com.

## Contact

You can contact us through either [`Discord`](https://discord.gg/sVN47RU) or [email](capsule-dev@googlegroups.com).

## Maintainers

The current maintainers with roles to merge PRs are:

* [Peter Cline](https://github.com/clinedome)
* [Daniel Jin](https://github.com/drunkirishcoder)
* [Zeeshan Lakhani](https://github.com/zeeshanlakhani)
* [Andrew Wang](https://github.com/awangc)

## License

This project is licensed under the [Apache-2.0 license](LICENSE).
