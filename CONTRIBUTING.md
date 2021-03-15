# Contributing to Capsule

Thank you for your help improving the project! No contribution is too small and all contributions are valued.

When contributing to this repository, please first discuss the change you wish to make via issue, [Discord](https://discord.gg/sAgzNV27sA) or [email](mailto:capsule-dev@googlegroups.com) with the `Capsule` [maintainers](https://github.com/orgs/capsule-rs/teams/maintainers/members) before making a change.

This guide will help you get started. Please note that we have a [Code of Conduct](CODE_OF_CONDUCT.md), please follow it in all your interactions with the project.

## Table of Contents

- [Contributing to Capsule](#contributing-to-capsule)
  - [Table of Contents](#table-of-contents)
  - [Code of Conduct](#code-of-conduct)
  - [Contributing in Issues](#contributing-in-issues)
    - [Asking for General Help](#asking-for-general-help)
    - [Submitting a Bug Report](#submitting-a-bug-report)
    - [Requesting a New Feature](#requesting-a-new-feature)
  - [Pull Requests](#pull-requests)
    - [Development Notes](#development-notes)
    - [Commits](#commits)
    - [Opening the Pull Request](#opening-the-pull-request)
    - [Contributor License Agreement](#contributor-license-agreement)
    - [Pull Request Approval](#pull-request-approval)

## Code of Conduct

This project and everyone participating in it are governed by the [Capsule Code Of Conduct](CODE_OF_CONDUCT.md).  By
participating, you agree to this Code. Please report any violations of the code of conduct to capsule-dev@googlegroups.com.

## Contributing in Issues

Work on `Capsule` is tracked by Github Issues. Anybody can participate in any stage of contribution. We encourage you to participate in the discussion around bugs and PRs.

### Asking for General Help

If you have reviewed existing documentation and still have questions or are having problems, you can join our [Discord](https://discord.gg/sAgzNV27sA) to ask for help. When applicable, we would appretiate it if you can contribute back a documentation PR that helps others avoid the problems that you encountered.

### Submitting a Bug Report

If you believe that you have uncovered a bug, please fill out the [bug report](.github/ISSUE_TEMPLATE/bug-report.md) form, following the template to the best of your ability. Do not worry if you cannot answer every detail, just fill in what you can.

The two most important pieces of information we need in order to properly evaluate the report is a description of the behavior you are seeing and a simple test case we can use to recreate the problem on our own.

### Requesting a New Feature

If you want a new feature added to `Capsule`, please fill out the [feature request](.github/ISSUE_TEMPLATE/feature-request.md) form.

There are no hard rules as to what features will or will not be accepted. It can be a network protocol, integrating with a feature in DPDK, or something new entirely. Ultimately, it depends on what the expected benefit is relative to the expected maintenance burden.

## Pull Requests

Pull requests which fix bugs, add features or improve documentation are welcome and greatly appretiated. Before making a large change, it is usually a good idea to first open an issue describing the change to solicit feedback and guidance. This will increase the likelihood of the PR getting merged.

### Development Notes

`Capsule` requires extra arguments to many common `cargo` commands typically use. We've simplified these commands with a set of [make targets](Makefile) so you don't have to remember them.

To check compilation of the workspace with all features enabled, use

```
make check
```

To run the unit tests, including those that are feature-gated, use

```
make test
```

We use [rustfmt](https://github.com/rust-lang/rustfmt) to maintain a consistent coding style. To automatically format your source code, use

```
make fmt
```

We use [Clippy](https://github.com/rust-lang/rust-clippy) to catch common Rust mistakes and follow best practices like [Rust 2018](https://doc.rust-lang.org/edition-guide/rust-2018/index.html) idioms. To lint the source code, use

```
make lint
```

When generating documentation normally, the markers that list the features required for various parts of `Capsule` are missing. To build the documentation correctly, install nightly Rust (`rustup install nightly`) and use

```
make docs
```

### Commits

It is a recommended best practice to keep your changes as logically grouped as possible within individual commits. There is no limit to the number of commits any single Pull Request may have. That said, if you have a number of commits that are "checkpoints" and don't represent a single logical change, please squash those together.

The first line of the commit message should
  * contain a short description of the change no more than 72 characters
  * start with an imperative verb in the present tense
  * be entirely in lowercase with the exception of proper nouns and acronyms

When necessary to include a longer commit message, keep the second line blank. You can use markdown syntax for the rest of the commit message.

Note that multiple commits may get squashed when they are merged.

### Opening the Pull Request

Opening a new Pull Request will present you with a [template](.github/pull_request_template.md) that should be filled out. Please try to do your best at filling out the details.

You will get feedback or requests for changes to your Pull Request. This is a big part of the submission process so don't be discouraged! This is a necessary part of the process in order to evaluate whether the changes are correct and necessary.

Any community member can review a PR and you might get conflicting feedback. Keep an eye out for comments from `Capsule` [maintainers](https://github.com/orgs/capsule-rs/teams/maintainers/members) to provide guidance on conflicting feedback.

### Contributor License Agreement

Before Comcast merges your code into the project you must sign the [Comcast Contributor License Agreement (CLA)](https://gist.github.com/ComcastOSS/a7b8933dd8e368535378cda25c92d19a).

If you haven't previously signed a Comcast CLA, you'll automatically be asked to when you open a pull request. Alternatively, we can send you a PDF that you can sign and scan back to us. Please create a new GitHub issue to request a PDF version of the CLA.

### Pull Request Approval

A Pull Request must be approved by at least one maintainer of `Capsule`. Once approved, a maintainer will merge it. If you are a maintainer, you can merge your Pull Request once you have the approval of another maintainer.
