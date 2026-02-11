# verify_caches.py — Run from project root: python verify_caches.py
# Standalone verification that cache architectures produce different results
from cache_architectures import create_cache

config = dict(cache_size=256, block_size=16, word_size=4, address_width=32)

# conflict_demo.txt addresses
trace = [
    (0x000,'R'), (0x010,'R'), (0x020,'R'), (0x030,'R'),
    (0x100,'R'), (0x110,'R'), (0x120,'R'), (0x130,'R'),
    (0x000,'R'), (0x010,'R'), (0x020,'R'), (0x030,'R'),
    (0x100,'R'), (0x110,'R'), (0x120,'R'), (0x130,'R'),
]

caches = [
    ("Direct-Mapped",      create_cache("Direct-Mapped",      **config)),
    ("Fully Associative",  create_cache("Fully Associative",   **config, replacement_policy="LRU")),
    ("4-way Set-Assoc",    create_cache("Set-Associative",     **config, associativity=4, replacement_policy="LRU")),
]

for name, cache in caches:
    print(f"\n=== {name} ===")
    for addr, op in trace:
        result = cache.access(addr, op)
        hm = "HIT " if result['hit'] else "MISS"
        print(f"  0x{addr:04X} -> tag={result['tag']}, idx={result['index']}, {hm}")
    stats = cache.get_statistics()
    print(f"  => Hits: {stats['hits']}, Misses: {stats['misses']}, Hit Rate: {stats['hit_rate']:.1f}%")
