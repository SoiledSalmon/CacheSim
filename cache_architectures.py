# cache_architectures.py
"""
Cache architecture implementations for educational simulation.

This module provides explicit implementations of three cache architectures:
- DirectMappedCache: Each block maps to exactly one cache line
- FullyAssociativeCache: Any block can map to any cache line
- SetAssociativeCache: Hybrid N-way associative within sets

All implementations support configurable parameters and multiple replacement policies.
"""

from abc import ABC, abstractmethod
import random


class BaseCache(ABC):
    """
    Abstract base class for all cache implementations.

    Provides shared functionality for address decomposition, statistics,
    and AMAT calculation. Subclasses must implement cache-specific behavior.
    """

    def __init__(self, cache_size, block_size, word_size=4,
                 address_width=32, replacement_policy='LRU'):
        """
        Initialize base cache parameters.

        Args:
            cache_size: Total cache size in bytes
            block_size: Size of each cache block in bytes
            word_size: Size of a word in bytes (1, 2, 4, or 8)
            address_width: Address bus width in bits (16, 32, or 64)
            replacement_policy: 'LRU', 'FIFO', or 'Random'
        """
        self.cache_size = cache_size
        self.block_size = block_size
        self.word_size = word_size
        self.address_width = address_width
        self.replacement_policy = replacement_policy

        # Derived parameters
        self.num_blocks = cache_size // block_size
        self.offset_bits = self._log2(block_size)

        # Statistics
        self.hits = 0
        self.misses = 0
        self.access_counter = 0  # Global counter for LRU/FIFO tracking

        # Access history for detailed logging
        self.access_history = []

        # Initialize cache structure (implemented by subclasses)
        self._initialize_cache()

    @staticmethod
    def _log2(x):
        """Calculate log base 2 of x (assumes x is power of 2)."""
        return (x.bit_length() - 1) if x > 0 else 0

    @abstractmethod
    def _initialize_cache(self):
        """Initialize the cache data structure. Must be implemented by subclasses."""
        pass

    @abstractmethod
    def access(self, address, operation='R'):
        """
        Access the cache at the given address.

        Args:
            address: Memory address to access
            operation: 'R' for read, 'W' for write

        Returns:
            dict with access results including hit/miss status
        """
        pass

    @abstractmethod
    def get_cache_state(self):
        """
        Get the current state of the cache for visualization.

        Returns:
            dict describing cache structure and contents
        """
        pass

    @abstractmethod
    def _get_num_sets(self):
        """Return the number of sets in this cache architecture."""
        pass

    @abstractmethod
    def _get_associativity(self):
        """Return the associativity of this cache architecture."""
        pass

    def decompose_address(self, address):
        """
        Decompose an address into tag, index, and offset components.

        Args:
            address: Memory address (integer)

        Returns:
            dict with tag, index, offset values and bit breakdown
        """
        binary_address = format(address, f'0{self.address_width}b')

        # Calculate index bits based on number of sets
        num_sets = self._get_num_sets()
        index_bits_count = self._log2(num_sets) if num_sets > 1 else 0

        # Explicit bit extraction with named ranges
        if self.offset_bits > 0:
            offset_bits_str = binary_address[-self.offset_bits:]
        else:
            offset_bits_str = ''

        if index_bits_count > 0 and self.offset_bits > 0:
            index_bits_str = binary_address[-(self.offset_bits + index_bits_count):-self.offset_bits]
        elif index_bits_count > 0:
            index_bits_str = binary_address[-index_bits_count:]
        else:
            index_bits_str = ''

        total_lower_bits = self.offset_bits + index_bits_count
        if total_lower_bits > 0:
            tag_bits_str = binary_address[:-total_lower_bits]
        else:
            tag_bits_str = binary_address

        # Handle empty strings
        tag = int(tag_bits_str, 2) if tag_bits_str else 0
        index = int(index_bits_str, 2) if index_bits_str else 0
        offset = int(offset_bits_str, 2) if offset_bits_str else 0

        tag_bits_count = self.address_width - index_bits_count - self.offset_bits

        return {
            'tag': tag,
            'index': index,
            'offset': offset,
            'binary': binary_address,
            'word_address': address // self.word_size,
            'breakdown': {
                'tag': {
                    'bits': tag_bits_str,
                    'value': tag,
                    'num_bits': tag_bits_count,
                    'range': f'[{self.address_width-1}:{self.offset_bits+index_bits_count}]' if tag_bits_count > 0 else 'N/A'
                },
                'index': {
                    'bits': index_bits_str,
                    'value': index,
                    'num_bits': index_bits_count,
                    'range': f'[{self.offset_bits+index_bits_count-1}:{self.offset_bits}]' if index_bits_count > 0 else 'N/A'
                },
                'offset': {
                    'bits': offset_bits_str,
                    'value': offset,
                    'num_bits': self.offset_bits,
                    'range': f'[{self.offset_bits-1}:0]' if self.offset_bits > 0 else 'N/A'
                }
            }
        }

    def get_statistics(self):
        """
        Get cache performance statistics.

        Returns:
            dict with hits, misses, hit_rate, miss_rate
        """
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        miss_rate = (self.misses / total * 100) if total > 0 else 0

        return {
            'hits': self.hits,
            'misses': self.misses,
            'total_accesses': total,
            'hit_rate': hit_rate,
            'miss_rate': miss_rate
        }

    def calculate_amat(self, hit_time=1, miss_penalty=100):
        """
        Calculate Average Memory Access Time.

        AMAT = Hit Time + (Miss Rate * Miss Penalty)

        Args:
            hit_time: Time for a cache hit (default: 1 cycle)
            miss_penalty: Additional time for a miss (default: 100 cycles)

        Returns:
            dict with AMAT value and formula breakdown
        """
        stats = self.get_statistics()
        miss_rate = stats['miss_rate'] / 100  # Convert percentage to decimal

        amat = hit_time + (miss_rate * miss_penalty)

        return {
            'amat': amat,
            'hit_time': hit_time,
            'miss_penalty': miss_penalty,
            'miss_rate': miss_rate,
            'formula': f'AMAT = {hit_time} + ({miss_rate:.4f} * {miss_penalty}) = {amat:.2f} cycles'
        }

    def reset(self):
        """Reset cache state and statistics."""
        self.hits = 0
        self.misses = 0
        self.access_counter = 0
        self.access_history = []
        self._initialize_cache()

    def get_config(self):
        """Get cache configuration for display."""
        return {
            'cache_size': self.cache_size,
            'block_size': self.block_size,
            'word_size': self.word_size,
            'address_width': self.address_width,
            'replacement_policy': self.replacement_policy,
            'num_blocks': self.num_blocks,
            'num_sets': self._get_num_sets(),
            'associativity': self._get_associativity(),
            'offset_bits': self.offset_bits,
            'index_bits': self._log2(self._get_num_sets()) if self._get_num_sets() > 1 else 0,
            'tag_bits': self.address_width - self.offset_bits - (self._log2(self._get_num_sets()) if self._get_num_sets() > 1 else 0)
        }


class DirectMappedCache(BaseCache):
    """
    Direct-mapped cache implementation.

    Each memory block maps to exactly one cache line.
    - num_sets = num_blocks
    - associativity = 1
    - No replacement policy needed (deterministic mapping)
    """

    def __init__(self, cache_size, block_size, word_size=4,
                 address_width=32, replacement_policy='LRU'):
        # Direct-mapped ignores replacement policy
        super().__init__(cache_size, block_size, word_size,
                        address_width, 'N/A (Direct-Mapped)')
        self.index_bits = self._log2(self.num_blocks)

    def _initialize_cache(self):
        """Initialize cache as list of (valid, tag) tuples."""
        # Each entry: (valid_bit, tag)
        self.cache = [(False, None) for _ in range(self.num_blocks)]

    def _get_num_sets(self):
        return self.num_blocks

    def _get_associativity(self):
        return 1

    def access(self, address, operation='R'):
        """Access cache with direct mapping."""
        self.access_counter += 1
        decomp = self.decompose_address(address)

        index = decomp['index']
        tag = decomp['tag']

        valid, cached_tag = self.cache[index]

        if valid and cached_tag == tag:
            # Cache hit
            self.hits += 1
            hit = True
            evicted_tag = None
        else:
            # Cache miss
            self.misses += 1
            hit = False
            evicted_tag = cached_tag if valid else None
            # Replace the line (no choice in direct-mapped)
            self.cache[index] = (True, tag)

        result = {
            'address': address,
            'operation': operation,
            'hit': hit,
            'tag': tag,
            'index': index,
            'offset': decomp['offset'],
            'evicted_tag': evicted_tag,
            'decomposition': decomp
        }

        self.access_history.append(result)
        return result

    def get_cache_state(self):
        """Get cache state for visualization."""
        lines = []
        for i, (valid, tag) in enumerate(self.cache):
            lines.append({
                'set': i,
                'way': 0,
                'valid': valid,
                'tag': tag,
                'tag_hex': hex(tag) if tag is not None else '---'
            })

        return {
            'type': 'Direct-Mapped',
            'num_sets': self.num_blocks,
            'associativity': 1,
            'lines': lines
        }


class FullyAssociativeCache(BaseCache):
    """
    Fully associative cache implementation.

    Any memory block can be placed in any cache line.
    - num_sets = 1
    - associativity = num_blocks
    - No index bits (entire address minus offset is the tag)
    - Requires replacement policy (LRU, FIFO, or Random)
    """

    def __init__(self, cache_size, block_size, word_size=4,
                 address_width=32, replacement_policy='LRU'):
        super().__init__(cache_size, block_size, word_size,
                        address_width, replacement_policy)
        self.index_bits = 0  # No index bits in fully associative

    def _initialize_cache(self):
        """Initialize cache as list of (valid, tag, counter) tuples."""
        # Each entry: (valid_bit, tag, lru_counter/insertion_order)
        self.cache = [(False, None, 0) for _ in range(self.num_blocks)]

    def _get_num_sets(self):
        return 1

    def _get_associativity(self):
        return self.num_blocks

    def _find_tag(self, tag):
        """Search all cache lines for matching tag."""
        for i, (valid, cached_tag, _) in enumerate(self.cache):
            if valid and cached_tag == tag:
                return i
        return -1

    def _find_victim(self):
        """Find victim line based on replacement policy."""
        # First, check for invalid lines
        for i, (valid, _, _) in enumerate(self.cache):
            if not valid:
                return i

        # All lines valid, apply replacement policy
        if self.replacement_policy == 'Random':
            return random.randint(0, self.num_blocks - 1)
        else:  # LRU or FIFO
            # Find line with smallest counter
            min_counter = float('inf')
            victim = 0
            for i, (_, _, counter) in enumerate(self.cache):
                if counter < min_counter:
                    min_counter = counter
                    victim = i
            return victim

    def access(self, address, operation='R'):
        """Access cache with full associativity."""
        self.access_counter += 1
        decomp = self.decompose_address(address)

        tag = decomp['tag']

        cache_line = self._find_tag(tag)

        if cache_line >= 0:
            # Cache hit
            self.hits += 1
            hit = True
            evicted_tag = None

            if self.replacement_policy == 'LRU':
                # Update LRU counter on hit
                valid, cached_tag, _ = self.cache[cache_line]
                self.cache[cache_line] = (valid, cached_tag, self.access_counter)
        else:
            # Cache miss
            self.misses += 1
            hit = False

            # Find victim
            victim = self._find_victim()
            valid, evicted_tag_val, _ = self.cache[victim]
            evicted_tag = evicted_tag_val if valid else None

            # Insert new line
            self.cache[victim] = (True, tag, self.access_counter)
            cache_line = victim

        result = {
            'address': address,
            'operation': operation,
            'hit': hit,
            'tag': tag,
            'index': 0,  # Always 0 for fully associative
            'offset': decomp['offset'],
            'cache_line': cache_line,
            'evicted_tag': evicted_tag,
            'decomposition': decomp
        }

        self.access_history.append(result)
        return result

    def get_cache_state(self):
        """Get cache state for visualization."""
        lines = []
        for i, (valid, tag, counter) in enumerate(self.cache):
            lines.append({
                'set': 0,
                'way': i,
                'valid': valid,
                'tag': tag,
                'tag_hex': hex(tag) if tag is not None else '---',
                'counter': counter
            })

        return {
            'type': 'Fully Associative',
            'num_sets': 1,
            'associativity': self.num_blocks,
            'lines': lines
        }


class SetAssociativeCache(BaseCache):
    """
    Set-associative cache implementation.

    Hybrid between direct-mapped and fully associative.
    - num_sets = num_blocks / associativity
    - Index selects set, then search within set
    - Generalizes: DM (assoc=1), FA (assoc=num_blocks)
    """

    def __init__(self, cache_size, block_size, associativity, word_size=4,
                 address_width=32, replacement_policy='LRU'):
        self.associativity = associativity
        super().__init__(cache_size, block_size, word_size,
                        address_width, replacement_policy)
        self.num_sets = self.num_blocks // associativity
        self.index_bits = self._log2(self.num_sets) if self.num_sets > 1 else 0

    def _initialize_cache(self):
        """Initialize cache as list of sets, each set is list of (valid, tag, counter)."""
        num_sets = self.num_blocks // self.associativity
        # Each set contains 'associativity' number of lines
        # Each line: (valid_bit, tag, lru_counter/insertion_order)
        self.cache = [
            [(False, None, 0) for _ in range(self.associativity)]
            for _ in range(num_sets)
        ]

    def _get_num_sets(self):
        return self.num_blocks // self.associativity

    def _get_associativity(self):
        return self.associativity

    def _find_tag_in_set(self, set_index, tag):
        """Search within a set for matching tag."""
        for way, (valid, cached_tag, _) in enumerate(self.cache[set_index]):
            if valid and cached_tag == tag:
                return way
        return -1

    def _find_victim_in_set(self, set_index):
        """Find victim within a set based on replacement policy."""
        cache_set = self.cache[set_index]

        # First, check for invalid lines
        for way, (valid, _, _) in enumerate(cache_set):
            if not valid:
                return way

        # All lines valid, apply replacement policy
        if self.replacement_policy == 'Random':
            return random.randint(0, self.associativity - 1)
        else:  # LRU or FIFO
            # Find line with smallest counter
            min_counter = float('inf')
            victim = 0
            for way, (_, _, counter) in enumerate(cache_set):
                if counter < min_counter:
                    min_counter = counter
                    victim = way
            return victim

    def access(self, address, operation='R'):
        """Access cache with set associativity."""
        self.access_counter += 1
        decomp = self.decompose_address(address)

        tag = decomp['tag']
        index = decomp['index']

        way = self._find_tag_in_set(index, tag)

        if way >= 0:
            # Cache hit
            self.hits += 1
            hit = True
            evicted_tag = None

            if self.replacement_policy == 'LRU':
                # Update LRU counter on hit
                valid, cached_tag, _ = self.cache[index][way]
                self.cache[index][way] = (valid, cached_tag, self.access_counter)
        else:
            # Cache miss
            self.misses += 1
            hit = False

            # Find victim within set
            victim_way = self._find_victim_in_set(index)
            valid, evicted_tag_val, _ = self.cache[index][victim_way]
            evicted_tag = evicted_tag_val if valid else None

            # Insert new line
            self.cache[index][victim_way] = (True, tag, self.access_counter)
            way = victim_way

        result = {
            'address': address,
            'operation': operation,
            'hit': hit,
            'tag': tag,
            'index': index,
            'way': way,
            'offset': decomp['offset'],
            'evicted_tag': evicted_tag,
            'decomposition': decomp
        }

        self.access_history.append(result)
        return result

    def get_cache_state(self):
        """Get cache state for visualization."""
        lines = []
        for set_idx, cache_set in enumerate(self.cache):
            for way, (valid, tag, counter) in enumerate(cache_set):
                lines.append({
                    'set': set_idx,
                    'way': way,
                    'valid': valid,
                    'tag': tag,
                    'tag_hex': hex(tag) if tag is not None else '---',
                    'counter': counter
                })

        return {
            'type': f'{self.associativity}-way Set Associative',
            'num_sets': self._get_num_sets(),
            'associativity': self.associativity,
            'lines': lines
        }


def create_cache(architecture, cache_size, block_size, associativity=None,
                 word_size=4, address_width=32, replacement_policy='LRU'):
    """
    Factory function to create cache instances.

    Args:
        architecture: 'Direct-Mapped', 'Fully Associative', or 'Set-Associative'
        cache_size: Total cache size in bytes
        block_size: Block size in bytes
        associativity: Number of ways (only for Set-Associative)
        word_size: Word size in bytes
        address_width: Address width in bits
        replacement_policy: 'LRU', 'FIFO', or 'Random'

    Returns:
        Appropriate cache instance
    """
    if architecture == 'Direct-Mapped':
        return DirectMappedCache(cache_size, block_size, word_size,
                                 address_width, replacement_policy)
    elif architecture == 'Fully Associative':
        return FullyAssociativeCache(cache_size, block_size, word_size,
                                     address_width, replacement_policy)
    elif architecture == 'Set-Associative':
        if associativity is None:
            raise ValueError("Associativity required for Set-Associative cache")
        return SetAssociativeCache(cache_size, block_size, associativity,
                                   word_size, address_width, replacement_policy)
    else:
        raise ValueError(f"Unknown architecture: {architecture}")
