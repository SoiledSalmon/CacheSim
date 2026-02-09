# Assumptions and Current Limitations

This document tracks the hardcoded assumptions in the cache simulator implementation and their planned resolution.

## Current Assumptions

| Assumption | Location | Why It Exists | Status | Resolution |
|------------|----------|---------------|--------|------------|
| 32-bit address width | `cache_simulator.py:37` (`'032b'`) | Simplified for demo, common architecture | **Resolved** | Parameterized via `address_width` in `cache_architectures.py` |
| 4-byte word size | `cache_simulator.py:36` (`// 4`) | Common x86/ARM architecture | **Resolved** | Parameterized via `word_size` in `cache_architectures.py` |
| LRU replacement only | `cache_simulator.py:18-20,52-53` | Simple to implement | **Resolved** | Added FIFO and Random policies in `cache_architectures.py` |
| Hardcoded memory trace | `gui.py:34-46` | Quick testing | **Resolved** | Externalized via trace input widget and file loading |
| Read-only operations | `gui.py:35-45` | Simplified model | **Documented** | Write operations accepted but not differentiated (no write-back/write-through distinction) |
| Tags stored as strings | `cache_simulator.py:40,42` | Easy string slicing | **Resolved** | Tags now stored as integers in `cache_architectures.py` |

## Architectural Decisions

### Address Decomposition

The address is decomposed into three parts:
- **Tag**: Upper bits used for cache line identification
- **Index**: Middle bits used to select the cache set
- **Offset**: Lower bits used to select byte within block

The number of bits for each field depends on:
- `offset_bits = log2(block_size)`
- `index_bits = log2(num_sets)` where `num_sets = num_blocks / associativity`
- `tag_bits = address_width - index_bits - offset_bits`

### Cache Architectures

| Architecture | Index Bits | Associativity | Description |
|--------------|------------|---------------|-------------|
| Direct-Mapped | log2(num_blocks) | 1 | Each block maps to exactly one cache line |
| Fully Associative | 0 | num_blocks | Any block can go in any cache line |
| Set-Associative | log2(num_sets) | N (configurable) | Hybrid: N-way within each set |

### Replacement Policies

| Policy | Description | Implementation |
|--------|-------------|----------------|
| LRU (Least Recently Used) | Evicts the least recently accessed line | Tracked via `lru_counter` per line |
| FIFO (First In First Out) | Evicts the oldest line | Tracked via `insertion_order` |
| Random | Evicts a randomly selected line | Uses Python's `random.choice()` |

## Memory Trace Format

The simulator accepts traces in the following format:
```
# Comment lines start with #
0x0A R    # Hexadecimal address with read operation
10 W      # Decimal address with write operation
0xFF      # Address only (defaults to Read)
```

## Legacy Code

The original `cache_simulator.py` is preserved as `cache_simulator_legacy.py` for reference. The new implementation in `cache_architectures.py` addresses all the limitations listed above.

## Future Considerations

- **Write policies**: Could add write-through vs write-back simulation
- **Multi-level cache**: L1/L2/L3 cache hierarchy
- **Cache coherence**: MESI protocol simulation for multi-core
- **Prefetching**: Hardware prefetch simulation
