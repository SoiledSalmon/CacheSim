# ADLD Cache Simulator

A comparative cache architecture simulator designed for computer architecture education. This tool provides explicit implementations of Direct-Mapped, Fully Associative, and Set-Associative caches with pedagogical visualizations.

## Features

- **Multiple Cache Architectures**
  - Direct-Mapped: Each block maps to exactly one cache line
  - Fully Associative: Any block can map to any cache line
  - Set-Associative: N-way associative within sets

- **Configurable Parameters**
  - Cache size, block size, and associativity
  - Word size (1, 2, 4, 8 bytes)
  - Address width (16, 32, 64 bits)
  - Replacement policies (LRU, FIFO, Random)

- **Pedagogical Visualizations**
  - Address decomposition with color-coded bit fields (Tag, Index, Offset)
  - Real-time cache state display
  - Step-by-step simulation mode
  - Side-by-side architecture comparison

- **Performance Metrics**
  - Hit/miss tracking and rates
  - AMAT (Average Memory Access Time) calculation
  - Comparative analysis across architectures

## Installation

### Requirements

- **Python 3.10+** (tested with Python 3.14)
- Tkinter (usually included with Python)

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/aksh1009/cache-simulator.git
   cd cache-simulator
   ```

2. Ensure Python 3.x is installed with Tkinter:
   ```bash
   # Windows/Mac - usually included with Python
   pip install tk

   # Linux
   sudo apt-get install python3-tk
   ```

3. Run the application:
   ```bash
   python main.py
   ```

## Usage

### Basic Simulation

1. Select cache architecture (Direct-Mapped, Fully Associative, or Set-Associative)
2. Configure cache parameters (size, block size, associativity)
3. Enter memory trace in the text area or load from file
4. Click "Run Full Simulation" or use "Step" for step-by-step execution

### Memory Trace Format

Traces are text files with one access per line:
```
# Comments start with #
0x0A R       # Hexadecimal address, Read operation
16 W         # Decimal address, Write operation
0xFF         # Address only (defaults to Read)
```

Sample traces are provided in the `sample_traces/` directory.

### Architecture Comparison

Click "Compare Architectures" to run the same trace on all three cache types simultaneously and view side-by-side hit rates and AMAT values.

## Project Structure

```
CacheSim/
├── main.py                     # Application entry point
├── gui.py                      # Tkinter GUI implementation
├── cache_architectures.py      # Cache implementations (BaseCache, DM, FA, SA)
├── cache_simulator_legacy.py   # Original implementation (deprecated)
├── ASSUMPTIONS.md              # Design decisions and limitations
├── PEDAGOGY.md                 # Educational feature mapping
├── CLAUDE.md                   # Development guidance
├── README.md                   # This file
└── sample_traces/              # Example memory traces
    ├── simple.txt
    ├── conflict_demo.txt
    └── sequential.txt
```

## Architecture Overview

### Class Hierarchy

```
BaseCache (ABC)
├── DirectMappedCache    (assoc=1, no replacement choice)
├── FullyAssociativeCache (no index bits, full search)
└── SetAssociativeCache   (N-way, index selects set)
```

### Address Decomposition

For a 32-bit address with 256-byte cache, 16-byte blocks, 4-way associativity:

```
Address: 0x000003A7 (935)
Binary:  00000000000000000000001110100111
         |----------- TAG ----------|IDX|OFF|
Tag:     0000000000000000000000111010  = 58
Index:   01                            = 1
Offset:  0111                          = 7
```

- **Offset bits** = log2(block_size) = 4 bits
- **Index bits** = log2(num_sets) = 2 bits (for 4 sets)
- **Tag bits** = address_width - offset_bits - index_bits = 26 bits

## Educational Concepts

| Concept | Simulator Feature |
|---------|-------------------|
| Address decomposition | Color-coded bit visualization |
| Hit/miss analysis | Per-access logging with results |
| Conflict misses | Compare DM vs FA architectures |
| Replacement policies | LRU, FIFO, Random selection |
| AMAT calculation | Configurable hit time and miss penalty |
| Trade-off analysis | Side-by-side comparison mode |

## AMAT Calculation

```
AMAT = Hit Time + (Miss Rate × Miss Penalty)
```

Default values: Hit Time = 1 cycle, Miss Penalty = 100 cycles

Example: With 80% hit rate (20% miss rate):
```
AMAT = 1 + (0.20 × 100) = 21 cycles
```

## Academic Simplifications

This simulator is designed for educational purposes and makes the following simplifications compared to real hardware:

| Real-World Feature | Simulator Approach |
|-------------------|-------------------|
| Multi-level caches (L1/L2/L3) | Single-level cache only |
| Separate I-cache and D-cache | Unified cache |
| Write policies (write-through/write-back) | Not modeled (no writes to memory) |
| Cache coherence protocols | Not applicable (single cache) |
| Prefetching | Not implemented |
| Non-blocking caches | Blocking access model |
| Variable latencies | Fixed hit time and miss penalty |

These simplifications allow focus on the core concepts of address decomposition, hit/miss analysis, and replacement policies as taught in ADLD coursework.

## License

MIT License

## Contributing

Contributions welcome! Please see CLAUDE.md for development guidelines.

