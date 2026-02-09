class CacheSimulator:
    def __init__(self, cache_size, block_size, associativity):
        self.cache_size = cache_size
        self.block_size = block_size
        self.associativity = associativity
        self.num_blocks = cache_size // block_size
        self.cache = [[] for _ in range(self.num_blocks)]
        self.hits = 0
        self.misses = 0
        self.index_bits = self._log2(self.num_blocks // associativity)
        self.offset_bits = self._log2(block_size)

    def _log2(self, x):
        return (x.bit_length() - 1) if x > 0 else 0

    def _lru_update(self, index, tag):
        self.cache[index].remove(tag)
        self.cache[index].append(tag)

    def display_cache(self, text_widget):
        text_widget.insert(tk.END, "Cache\n")
        text_widget.insert(tk.END, "-" * 120 + "\n")
        text_widget.insert(tk.END, " ")
        for i in range(self.associativity):
            text_widget.insert(tk.END, f"{i:<28}")
        text_widget.insert(tk.END, "\n" + "-" * 120 + "\n")
        for i, cache_set in enumerate(self.cache):
            text_widget.insert(tk.END, f"Set {i:<2} | ")
            for tag in cache_set:
                text_widget.insert(tk.END, f"{tag:<28}")
            text_widget.insert(tk.END, "\n" + "-" * 120 + "\n")

    def access_memory(self, address, text_widget):
        word_address = address // 4
        binary_address = format(address, '032b')
        offset = int(binary_address[-self.offset_bits:], 2)
        index = int(binary_address[-(self.offset_bits + self.index_bits):-self.offset_bits], 2)
        tag = binary_address[:-self.offset_bits]

        if tag in self.cache[index]:
            self.hits += 1
            hit_or_miss = "HIT"
            self._lru_update(index, tag)
        else:
            self.misses += 1
            hit_or_miss = "MISS"
            if len(self.cache[index]) < self.associativity:
                self.cache[index].append(tag)
            else:
                self.cache[index].pop(0)
                self.cache[index].append(tag)

        text_widget.insert(tk.END, "{:<15}{:<40}{:<40}{:<40}{:<40}{:<30}\n".format(
            word_address, binary_address, tag, index, offset, hit_or_miss))

    def simulate_memory_accesses(self, memory_accesses, text_widget):
        text_widget.insert(tk.END, "{:<15}{:<40}{:<40}{:<40}{:<40}{:<30}\n".format(
            "WordAddr", "BinAddr", "Tag", "Index", "Offset", "Hit/Miss"))
        text_widget.insert(tk.END, "-" * 250 + "\n")
        for address, _ in memory_accesses:
            self.access_memory(address, text_widget)
        text_widget.insert(tk.END, "-" * 250 + "\n")
        self.display_cache(text_widget)

    def print_stats(self, text_widget):
        text_widget.insert(tk.END, "\n" + "-" * 60 + "\n")
        text_widget.insert(tk.END, "Simulation Statistics\n")
        text_widget.insert(tk.END, f"Cache Size: {self.cache_size} bytes\n")
        text_widget.insert(tk.END, f"Block Size: {self.block_size} bytes\n")
        text_widget.insert(tk.END, f"Associativity: {self.associativity}\n")
        text_widget.insert(tk.END, f"Number of Blocks: {self.num_blocks}\n")
        text_widget.insert(tk.END, f"Number of Hits: {self.hits}\n")
        text_widget.insert(tk.END, f"Number of Misses: {self.misses}\n")

        # Calculate and display hit rate only if there are hits and misses
        if self.hits + self.misses > 0:
            hit_rate = self.hits / (self.hits + self.misses) * 100
            text_widget.insert(tk.END, f"Hit Rate: {hit_rate:.2f}%\n")
        else:
            text_widget.insert(tk.END, "Hit Rate: N/A\n")
