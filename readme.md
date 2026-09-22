# SHA-256 Assembly & GPU Cracker

A high-performance **SHA-256 brute-force and wordlist research tool**, built around a hand-written **x86-64 FASM assembly engine** for the CPU, with an optional **OpenCL GPU engine**, both driven by the same Node.js GUI.

The project was created as an experiment in low-level performance engineering: how far can a manually optimized assembly implementation — and, alongside it, a GPU kernel — push SHA-256 candidate generation and verification on ordinary consumer hardware?

> **Current peak benchmark:** 29,533,892 candidates/sec on an AMD Ryzen 5 7500F (CPU/ASM engine).

---

## Features

* ⚡ Hand-written x86-64 Assembly SHA-256 engine
* 🎮 OpenCL GPU engine (NVIDIA, AMD, Intel Arc, and integrated GPUs)
* 🔀 Runtime selector in the GUI — pick CPU or GPU per run
* 🔎 Automatic GPU device detection, with per-device specs (compute units, clock, VRAM)
* 🔥 Brute-force candidate generation on both engines
* 📖 Wordlist-based candidate checking (CPU engine)
* 🧵 Native multithreading using Windows threads (CPU engine)
* 🖥️ Automatic logical-processor detection (CPU engine)
* 📊 Live overall throughput
* 📈 Peak-speed tracking
* 👷 Per-worker telemetry (CPU engine)
* 🛑 Early termination when a match is found
* 🔒 Private worker contexts for thread-safe hashing
* ⚙️ 64-bit candidate counters
* 🚀 Node.js GUI with a shared Assembly / GPU performance backend
* 🪶 Zero-SDK GPU build — `checker_gpu.exe` loads `OpenCL.dll` at runtime via `LoadLibraryA`, so no OpenCL SDK is needed to compile it
* 🧪 Designed for benchmarking and experimentation

---

# Performance

The engine has been tested on multiple CPUs, and works on any GPU exposing an OpenCL driver.

## AMD Ryzen 5 7500F — CPU / ASM engine
(tested by myself)
**Peak: 29,533,892 candidates/sec**

Approximately:

* **29.53 million candidates/sec**
* **1.77 billion candidates/minute**
* **106.3 billion candidates/hour** at the measured peak rate

The peak number is a benchmark measurement and should not be interpreted as a guaranteed sustained throughput.

## GPU / OpenCL engine

GPU throughput depends heavily on the device (discrete vs. integrated GPU, compute unit count, clock speed, driver, and workload), so there is no single reference number the way there is for the ASM benchmark above. Use the built-in **GPU device scan** (see below) to see your own hardware's specs, and the GUI's live **TRIED / SPEED / PEAK SPEED** telemetry to measure your own throughput during a run.

As a rough point of reference, even a modest integrated GPU (an 18-compute-unit Intel iGPU) has been observed sustaining low double-digit millions of candidates/sec in testing — competitive with or exceeding a multi-core CPU run on the same machine, without dedicating the CPU to the search.

Note: unlike the CPU engine, the GPU engine reports progress once per kernel-dispatch batch (16,777,216 candidates per batch) rather than continuously, so on small search spaces you may see very few `PROGRESS` updates — or the run may complete inside a single batch — before jumping straight to a result.

---

# How It Works

The performance-critical portion of the application is written in x86-64 Assembly (CPU engine) or OpenCL C (GPU engine). The Node.js application provides the user interface, lets you pick which engine to run, and communicates with whichever native binary is selected.

```text
┌─────────────────────┐
│      Node.js GUI    │
└──────────┬──────────┘
           │
           ▼
   ┌───────┴────────┐
   │ Runtime choice │
   └───────┬────────┘
           │
   ┌───────┴────────────────────────────┐
   ▼                                    ▼
┌─────────────────────┐      ┌───────────────────────┐
│ Native ASM Engine   │      │ Native GPU Engine     │
│ (checker.exe)       │      │ (checker_gpu.exe)     │
└──────────┬──────────┘      └──────────┬────────────┘
           │                            │
           ▼                            ▼
┌─────────────────────┐      ┌───────────────────────┐
│ Worker Threads      │      │ OpenCL device + queue │
│                     │      │ (auto-detected)       │
│ Worker 0            │      └──────────┬────────────┘
│ Worker 1            │                 │
│ Worker 2            │                 ▼
│ Worker ...          │      ┌───────────────────────┐
└──────────┬──────────┘      │ Batched NDRange kerne │
           │                 │ dispatch (16M/batch)  │
           ▼                 └──────────┬────────────┘
┌─────────────────────┐                 │
│ SHA-256 Compression │                 ▼
└──────────┬──────────┘      ┌───────────────────────┐
           │                 │ SHA-256 Compression   │
           ▼                 │ (per work-item)       │
┌─────────────────────┐      └──────────┬────────────┘
│ 32-byte comparison  │                 │
└─────────────────────┘                 ▼
                              ┌───────────────────────┐
                              │ 32-byte comparison    │
                              └───────────────────────┘
```

Each CPU worker receives its own working context, allowing multiple threads to perform hashing without sharing mutable SHA-256 working buffers. The brute-force search space is partitioned between workers so that different workers process different candidate ranges.

On the GPU side, each OpenCL work-item decodes its own candidate string from its global index (mixed-radix expansion over the chosen character set), hashes it in a single SHA-256 compression block, and compares it against the target digest — thousands of work-items run per dispatch.

---

# Runtimes: CPU (ASM) vs. GPU (OpenCL)

The GUI's **RUNTIME** selector lets you choose which engine runs your job. The two engines are not fully interchangeable:

| | CPU / ASM engine | GPU / OpenCL engine |
|---|---|---|
| Modes supported | Wordlist **and** brute-force | Brute-force only |
| Device selection | Automatic (all logical processors) | Choose a specific detected GPU |
| Per-thread / per-device telemetry | Yes — live worker panel | No — GPU throughput is reported in aggregate only |
| Progress reporting | Continuous | Once per 16M-candidate batch |
| Build dependency | FASM assembler | Plain C compiler only (OpenCL loaded dynamically at runtime, no SDK needed) |

If you switch to GPU while a wordlist run is configured, the GUI automatically switches you to brute-force mode, since `checker_gpu.exe` doesn't implement wordlist checking.

## GPU device detection

Before starting a GPU run, the GUI calls `checker_gpu.exe list`, which enumerates every OpenCL platform/device pair visible to your driver (CPU, GPU, and accelerator devices alike) and reports each one's name, compute unit count, clock speed, and memory size. The GUI filters this into a device dropdown so you can pick the exact GPU to run on — useful on machines with both an integrated and a discrete GPU. Use the rescan button in the GUI if you plug in or enable a device after the page has loaded.

You can also run device detection manually from a terminal:

```bash
checker_gpu.exe list
```

---


# Installation

## Requirements

* Windows x64
* Node.js
* Git
* A CPU supporting the required x86-64 instruction set (for the ASM engine)
* A GPU driver that ships `OpenCL.dll` — NVIDIA, AMD, and Intel drivers (including integrated GPUs) all include this by default (for the GPU engine; optional)
* The native Assembly and GPU engines included in this repository

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

## 3. Build the native engines

```bash
npm run build
```

This assembles `checker.exe` (CPU/ASM engine) and compiles `checker_gpu.exe` (GPU/OpenCL engine). The GPU engine needs only a plain C compiler (e.g. MinGW-w64/gcc) — it declares the small subset of the OpenCL host API it needs itself and loads `OpenCL.dll` at runtime, so no OpenCL SDK installation is required to build it. If no OpenCL-capable driver is present on the machine at run time, the GPU runtime option will report that no devices were found instead of failing to start.

## 4. Start the application

Open a terminal in the project directory:

```bash
npm start
```

The application will start the Node.js GUI/server and make both the Assembly and GPU engines available to the interface.

---

# Benchmarking

For meaningful performance comparisons:

1. Close unnecessary CPU/GPU-intensive applications.
2. Use the same candidate configuration (character set, length range) across runs.
3. Run the benchmark for a sufficiently long period.
4. Record both **peak** and **sustained** throughput.
5. Record the exact CPU model, and for GPU runs, the exact GPU model as reported by the device scan.
6. Record the number of CPU workers used, or the GPU device index selected.
7. Avoid comparing peak results from different workloads or between the CPU and GPU engines directly — they parallelize very differently, so "workers" and "compute units" are not equivalent units.
8. For GPU runs, remember progress updates arrive once per 16M-candidate batch, so very short runs may not show a stable sustained-speed reading — let it run through a few batches before recording numbers.

### Recommended benchmark information (CPU)

```text
CPU: Intel core i5 12th gen
Architecture: x86-64
Logical processors: 12
OS: windows 10
Worker count: 12
Average speed: 25M candidates/sec
Peak speed: 30M candidates/sec
```

### Recommended benchmark information (GPU)

```text
GPU: <as reported by checker_gpu.exe list>
Compute units: <CU count>
Clock: <MHz>
VRAM: <MB>
OS: windows 10
Average speed: <observed candidates/sec>
Peak speed: <observed candidates/sec>
```

Peak throughput is useful for observing the maximum performance reached by the engine, while sustained throughput is more representative of long-running workloads.

---

# Why Assembly (and now OpenCL)?

The project was created primarily as a low-level performance experiment.

Instead of implementing the hashing engine entirely in a high-level language, the performance-critical path is manually implemented in x86-64 Assembly for the CPU, and in OpenCL C for the GPU — each mapped to how its target hardware actually parallelizes work.

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
* GPU work-item indexing and batch sizing
* host/device buffer transfers

The project is also an experiment in understanding how much performance can be extracted from relatively modest hardware — CPU or GPU — through careful low-level optimization.

---

# Project Goals

The main goals are:

* Learn x86-64 Assembly through a real-world workload
* Learn GPU compute (OpenCL) as a point of comparison against the ASM engine
* Understand SHA-256 internally
* Experiment with CPU-level and GPU-level optimization
* Study multithreaded and massively-parallel workload partitioning
* Benchmark different CPU architectures and GPU devices
* Compare low-level implementations across hardware types
* Build a complete Assembly- and GPU-powered application rather than an isolated hashing function

This project is primarily intended as a **learning, benchmarking, and security research project**.

---

# Security & Legal Notice

This software is provided for **authorized testing, education, research, and benchmarking only**. This applies equally to the CPU/ASM engine and the GPU/OpenCL engine.

SHA-256 is a cryptographic hash function. A brute-force or wordlist search can potentially be used to recover a plaintext from a hash when the search space is sufficiently small or predictable — and a GPU engine can search that space faster, which does not change what is and isn't authorized use.

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
* GPU model and driver version
* thermal conditions
* operating system
* background processes
* compiler/assembler version
* workload
* candidate length
* character set
* thread scheduling
* implementation version

Therefore, benchmark numbers from different systems — and between the CPU and GPU engines — should not be treated as directly equivalent unless the methodology and workload are identical.

---

# License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

# Author

Built as a personal low-level performance engineering project.

**Assembly + OpenCL + SHA-256 + multithreading + a lot of optimization.**