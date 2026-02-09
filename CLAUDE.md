# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the Application

```bash
# Activate virtual environment (Windows)
.venv\Scripts\Activate.ps1

# Run the GUI application
python main.py
```

Tkinter is required (usually bundled with Python). If missing: `pip install tk` (Windows/Mac) or `sudo apt-get install python3-tk` (Linux).

## Architecture

This is an educational cache memory simulator with a Tkinter GUI, supporting multiple cache architectures:

### File Structure

- **main.py**: Entry point - creates Tkinter root window and instantiates the GUI
- **gui.py**: `CacheSimulatorGUI` class - comprehensive GUI with configuration panels, visualizations, and simulation controls
- **cache_architectures.py**: Core cache implementations
  - `BaseCache` (ABC): Abstract base with shared functionality
  - `DirectMappedCache`: Associativity = 1, no replacement policy
  - `FullyAssociativeCache`: No index bits, full search, requires replacement policy
  - `SetAssociativeCache`: N-way associative, index selects set
  - `create_cache()`: Factory function for cache instantiation
- **cache_simulator_legacy.py**: Original implementation (deprecated, kept for reference)

### Documentation

- **README.md**: User-facing documentation with usage guide
- **ASSUMPTIONS.md**: Documents design decisions and resolved limitations
- **PEDAGOGY.md**: Maps lecture concepts to simulator features

### Sample Traces

Located in `sample_traces/` directory:
- `simple.txt`: Basic sequential access pattern
- `conflict_demo.txt`: Demonstrates conflict misses in direct-mapped
- `sequential.txt`: Spatial locality demonstration

## Cache Implementation Details

### BaseCache (Abstract)

Provides shared functionality:
- `decompose_address(address)`: Returns dict with tag, index, offset, and bit breakdown
- `get_statistics()`: Returns hits, misses, hit_rate, miss_rate
- `calculate_amat(hit_time, miss_penalty)`: AMAT calculation with formula
- `reset()`: Clears cache state and statistics
- `get_config()`: Returns cache configuration for display

### Subclass-specific Behavior

**DirectMappedCache**:
- `_get_num_sets()` returns `num_blocks`
- `_get_associativity()` returns `1`
- Cache structure: `[(valid, tag), ...]`

**FullyAssociativeCache**:
- `_get_num_sets()` returns `1`
- `_get_associativity()` returns `num_blocks`
- Cache structure: `[(valid, tag, counter), ...]`
- Supports LRU, FIFO, Random replacement

**SetAssociativeCache**:
- `_get_num_sets()` returns `num_blocks // associativity`
- `_get_associativity()` returns configured associativity
- Cache structure: `[[(valid, tag, counter), ...], ...]`
- Supports LRU, FIFO, Random replacement

### Key Parameters

All caches support:
- `cache_size`: Total cache size in bytes
- `block_size`: Size of each cache block in bytes
- `word_size`: Word size in bytes (1, 2, 4, 8)
- `address_width`: Address bus width (16, 32, 64 bits)
- `replacement_policy`: 'LRU', 'FIFO', or 'Random'

SetAssociativeCache additionally requires:
- `associativity`: Number of ways per set

## GUI Structure

The GUI uses a paned window layout:

**Left Panel (Configuration)**:
- Cache Configuration: Architecture, size, block size, associativity, word size, address width, policy
- Memory Trace: Text input with load/clear buttons
- Simulation Controls: Run, Reset, Step, Compare buttons
- AMAT Parameters: Hit time, miss penalty

**Right Panel (Visualization)**:
- Address Decomposition: Color-coded bit visualization (Tag=red, Index=blue, Offset=green)
- Cache State: Treeview showing sets and ways with tags
- Access Log: Scrollable log with hit/miss highlighting
- Statistics: Configuration summary and AMAT calculation

## Memory Trace Format

```
# Comments start with #
0x0A R       # Hexadecimal address, Read operation
16 W         # Decimal address, Write operation
0xFF         # Address only (defaults to Read)
```

Parsing handled by `_parse_trace()` method in GUI.
