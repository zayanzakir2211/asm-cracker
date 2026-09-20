# SHA-256 Assembly Cracker

A high-performance **SHA-256 brute-force and wordlist research tool** built around a hand-written **x86-64 FASM assembly engine**, with a Node.js GUI.

The project was created as an experiment in low-level performance engineering: how far can a manually optimized assembly implementation push SHA-256 candidate generation and verification on ordinary CPUs?

> **Current peak benchmark:** 29,533,892 candidates/sec on an AMD Ryzen 5 7500F.

---

## Features

* ⚡ Hand-written x86-64 Assembly SHA-256 engine
* 🔥 Brute-force candidate generation
* 📖 Wordlist-based candidate checking
* 🧵 Native multithreading using Windows threads
* 🖥️ Automatic logical-processor detection
* 📊 Live overall throughput
* 📈 Peak-speed tracking
* 👷 Per-worker telemetry
* 🛑 Early termination when a match is found
* 🔒 Private worker contexts for thread-safe hashing
* ⚙️ 64-bit candidate counters
* 🚀 Node.js GUI with an Assembly performance engine
* 🧪 Designed for benchmarking and experimentation

---

# Performance

The engine has been tested on multiple CPUs.

## AMD Ryzen 5 7500F
(tested by myself)
**Peak: 29,533,892 candidates/sec**

Approximately:

* **29.53 million candidates/sec**
* **1.77 billion candidates/minute**
* **106.3 billion candidates/hour** at the measured peak rate

The peak number is a benchmark measurement and should not be interpreted as a guaranteed sustained throughput.

---

# How It Works

The performance-critical portion of the application is written in x86-64 Assembly.

The Node.js application provides the user interface and communicates with the native engine.

```text
┌─────────────────────┐
│      Node.js GUI    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Native ASM Engine   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Worker Threads      │
│                     │
│ Worker 0             │
│ Worker 1             │
│ Worker 2             │
│ Worker ...           │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ SHA-256 Compression │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ 32-byte comparison  │
└─────────────────────┘
```

Each worker receives its own working context, allowing multiple threads to perform hashing without sharing mutable SHA-256 working buffers.

The brute-force search space is partitioned between workers so that different workers process different candidate ranges.

---


# Installation

## Requirements

* Windows x64
* Node.js
* Git
* A CPU supporting the required x86-64 instruction set
* The native Assembly engine included in this repository

## 1. Clone the repository

```bash
git clone https://github.com/zayanzakir2211/asm-cracker.git
cd asm-cracker
```

## 2. Install Node.js

Download and install Node.js from the official website:

https://nodejs.org/

Verify the installation:

```bash
node --version
npm --version
```

## 3. Start the application

Open a terminal in the project directory:

```bash
npm start
```

The application will start the Node.js GUI/server and make the Assembly engine available to the interface.

---

# Benchmarking

For meaningful performance comparisons:

1. Close unnecessary CPU-intensive applications.
2. Use the same candidate configuration.
3. Run the benchmark for a sufficiently long period.
4. Record both **peak** and **sustained** throughput.
5. Record the exact CPU model.
6. Record the number of workers used.
7. Avoid comparing peak results from different workloads.

### Recommended benchmark information

```text
CPU: Intel core i5 12th gen
Architecture: x86-64
Logical processors: 12
OS: windows 10
Worker count: 12
Average speed: 25M candidates/sec
Peak speed: 30M candidates/sec
```

Peak throughput is useful for observing the maximum performance reached by the engine, while sustained throughput is more representative of long-running workloads.

---

# Why Assembly?

The project was created primarily as a low-level performance experiment.

Instead of implementing the hashing engine entirely in a high-level language, the performance-critical path is manually implemented in x86-64 Assembly.

This allows direct control over:

* CPU registers
* memory access
* instruction selection
* loop structure
* worker contexts
* candidate generation
* synchronization
* SHA-256 compression
* hot-loop overhead

The project is also an experiment in understanding how much performance can be extracted from relatively modest hardware through careful low-level optimization.

---

# Project Goals

The main goals are:

* Learn x86-64 Assembly through a real-world workload
* Understand SHA-256 internally
* Experiment with CPU-level optimization
* Study multithreaded workload partitioning
* Benchmark different CPU architectures
* Compare low-level implementations
* Build a complete Assembly-powered application rather than an isolated hashing function

This project is primarily intended as a **learning, benchmarking, and security research project**.

---

# Security & Legal Notice

This software is provided for **authorized testing, education, research, and benchmarking only**.

SHA-256 is a cryptographic hash function. A brute-force or wordlist search can potentially be used to recover a plaintext from a hash when the search space is sufficiently small or predictable.

You are responsible for ensuring that you have authorization to test any hash, system, dataset, password, credential, or other data.

### Do not use this software to:

* Access accounts that do not belong to you
* Recover credentials without authorization
* Attack third-party systems
* Circumvent authentication
* Process stolen credential databases
* Perform unauthorized security testing
* Violate applicable laws or terms of service

Use it only with hashes and systems for which you have permission.

The authors are not responsible for misuse of this software.

---

# Disclaimer

This project is provided **"as is"**, without warranties of any kind.

Benchmark results depend on:

* CPU model
* CPU frequency
* thermal conditions
* operating system
* background processes
* compiler/assembler version
* workload
* candidate length
* character set
* thread scheduling
* implementation version

Therefore, benchmark numbers from different systems should not be treated as directly equivalent unless the methodology and workload are identical.

---

# License

 All rights are reserved by the copyright holder.

---

# Author

Built as a personal low-level performance engineering project.

**Assembly + SHA-256 + multithreading + a lot of optimization.**