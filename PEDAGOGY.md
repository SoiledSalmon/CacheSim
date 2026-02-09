# Pedagogy Guide

This document maps computer architecture lecture concepts to simulator features, designed for ADLD (Advanced Digital Logic Design) coursework.

## Concept Mapping

| Lecture Concept | Simulator Feature | How to Demonstrate |
|-----------------|-------------------|-------------------|
| Address decomposition | Address Decomposition panel | Step through any access to see color-coded Tag/Index/Offset breakdown |
| Direct-mapped cache | Architecture selector | Select "Direct-Mapped" and observe single-way operation |
| Fully associative cache | Architecture selector | Select "Fully Associative" and note Index=0 (no index bits) |
| Set-associative cache | Architecture selector | Select "Set-Associative" with various associativity values |
| Cache hits/misses | Access Log panel | Each access shows HIT (green) or MISS (red) |
| Conflict misses | Compare Architectures | Load `conflict_demo.txt` and compare DM vs FA |
| Capacity misses | Trace analysis | Run sequential trace larger than cache size |
| LRU replacement | Policy selector + Step mode | Step through trace to see LRU evictions |
| FIFO replacement | Policy selector | Compare FIFO vs LRU on same trace |
| AMAT calculation | Statistics panel | View AMAT formula with configurable hit/miss times |

## Demonstration Scenarios

### Scenario 1: Understanding Address Bits

**Goal:** Show how address width, cache size, and block size affect bit allocation.

**Steps:**
1. Set Cache Size = 256 bytes, Block Size = 16 bytes
2. For Direct-Mapped: observe 16 sets, 4 index bits
3. For 4-way Set-Associative: observe 4 sets, 2 index bits
4. For Fully Associative: observe 0 index bits

**Key Insight:** More associativity = fewer index bits = more tag bits

### Scenario 2: Conflict Miss Demonstration

**Goal:** Show why direct-mapped caches suffer from conflict misses.

**Steps:**
1. Load `sample_traces/conflict_demo.txt`
2. Set Cache Size = 256, Block Size = 16
3. Run as Direct-Mapped: observe many misses
4. Click "Compare Architectures"
5. Note: FA has more hits because it avoids conflicts

**Key Insight:** Direct-mapped forces eviction even when cache has empty lines in other sets

### Scenario 3: Replacement Policy Comparison

**Goal:** Compare LRU vs FIFO behavior.

**Steps:**
1. Create trace with temporal locality pattern
2. Run with LRU, note hit rate
3. Reset and run with FIFO
4. Compare statistics

**Key Insight:** LRU exploits temporal locality better than FIFO

### Scenario 4: AMAT Trade-offs

**Goal:** Understand how hit rate affects average memory access time.

**Steps:**
1. Run simulation with current cache settings
2. Note hit rate in Statistics panel
3. Adjust Hit Time and Miss Penalty
4. Observe AMAT formula breakdown

**Key Formula:**
```
AMAT = Hit Time + (Miss Rate × Miss Penalty)
```

## PPT Slide Alignment

If your course uses specific slides, here's how to align:

### Cache Basics (Slides 1-10 typically)
- Use simulator's Configuration panel to set parameters
- Address Decomposition panel shows exact bit breakdown
- Statistics panel shows cache geometry

### Direct-Mapped Cache (Slides 11-20 typically)
- Select "Direct-Mapped" architecture
- Step through trace to see deterministic mapping
- Note: no replacement policy needed

### Associative Caches (Slides 21-35 typically)
- Toggle between FA and SA to compare
- Use "Compare Architectures" for side-by-side
- Demonstrate replacement policy effects

### Cache Performance (Slides 36-50 typically)
- Focus on Statistics panel
- AMAT calculation with formula breakdown
- Compare architectures to show trade-offs

## Lab Exercise Suggestions

### Lab 1: Cache Configuration
Have students predict bit allocation before running, then verify with simulator.

### Lab 2: Trace Analysis
Provide custom trace files and have students predict hit/miss sequence.

### Lab 3: Architecture Comparison
Use comparison mode to analyze which architecture works best for different access patterns.

### Lab 4: Performance Optimization
Given an AMAT target, have students find optimal cache configuration.

## Assessment Ideas

1. **Calculation Verification**: Hand-calculate address decomposition, verify with simulator
2. **Pattern Recognition**: Identify access patterns that favor each architecture
3. **Design Trade-offs**: Given constraints (cost, power), select appropriate cache design
4. **Performance Analysis**: Explain why certain traces favor certain architectures
