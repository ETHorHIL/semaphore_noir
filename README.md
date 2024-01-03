# Semaphore Implementation in Noir

This repository contains an implementation of [Semaphore](https://github.com/semaphore-protocol/semaphore/blob/main/packages/circuits/semaphore.circom) using [Noir](https://noir-lang.org/), ait can serve as a practical example for those interested in cryptographic circuits.

## Project Overview

The focus here is on leveraging Noir's capabilities for building Semaphore circuits. Noir's syntax is Rust-like, and its built-in support for cryptographic primitives like Poseidon, make it a great choice for this implementation. The Semaphore logic just uses 40 LOC. Even with limited ZK background its easy to effectively use Noir.

### Prerequisites

A basic understanding of the intended build is sufficient. Familiarity with Rust or the proof system underlying Noir is not required. The [standard Noir tutorial](https://noir-lang.org/) provides enough groundwork to get started.

## Installation Guide

Very easy: just clone the repo. The main.nr file contains the whole logic required and two tests. I install nargo and run `nargo check`, `nargo prove`, `nargo verify`.

## Disclaimer

I am an amateur dev, this code contains bugs and should not be used in serious settings.
