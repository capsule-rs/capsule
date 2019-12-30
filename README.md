[![CI -Github Actions](https://github.com/williamofockham/nb2/workflows/CI/badge.svg)](https://github.com/williamofockham/nb2/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/williamofockham/nb2/branch/master/graph/badge.svg)](https://codecov.io/gh/williamofockham/nb2)

# nb2

A framework for network function development. Written in Rust, inspired by [NetBricks](http://netbricks.io/) and built on Intel's [Data Plane Development Kit](https://www.dpdk.org/).

# Overview

The project is currently undergoing heavy development. The goal is to offer an ergonomic framework for network function development that traditionally has high barriers of entry for engineers. We are building a tool to efficiently manipulate network packets while being type-safe, memory-safe, and thread-safe.

# Quickstart

We are working on better documentation and a "Getting started" guide. For now, if you are interested in trying out the pre-release bits, head over to our [docker images](https://github.com/williamofockham/utils) repo and follow the directions to create a local development environment with DPDK and nb2. Afterward, dig around the examples and see for yourself how easy it is to write a program that can filter, parse, and create network packets.
