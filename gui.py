# gui.py
"""
Cache Simulator GUI - Educational visualization tool for ADLD coursework.

Provides a graphical interface for simulating and comparing different cache
architectures with pedagogical visualizations of address decomposition and
cache state.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from cache_architectures import (
    create_cache, DirectMappedCache, FullyAssociativeCache, SetAssociativeCache
)


class CacheSimulatorGUI:
    """Main GUI class for the cache simulator."""

    def __init__(self, master):
        self.master = master
        self.master.title("ADLD Cache Simulator - Educational Tool")
        self.master.geometry("1400x900")
        self.master.minsize(1200, 800)

        self.cache = None
        self.current_access_index = 0
        self.parsed_trace = []

        self._create_widgets()
        self._setup_layout()

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Main container with paned windows
        self.main_paned = ttk.PanedWindow(self.master, orient=tk.HORIZONTAL)

        # Left panel - Configuration and Controls
        self.left_frame = ttk.Frame(self.main_paned, padding="5")
        self._create_config_panel()
        self._create_trace_panel()
        self._create_control_panel()
        self._create_amat_panel()

        # Right panel - Visualizations
        self.right_frame = ttk.Frame(self.main_paned, padding="5")
        self._create_address_viz_panel()
        self._create_cache_viz_panel()
        self._create_log_panel()
        self._create_stats_panel()

    def _create_config_panel(self):
        """Create cache configuration panel."""
        config_frame = ttk.LabelFrame(self.left_frame, text="Cache Configuration", padding="10")
        config_frame.pack(fill=tk.X, pady=5)

        # Architecture selector
        ttk.Label(config_frame, text="Architecture:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.arch_var = tk.StringVar(value="Set-Associative")
        self.arch_combo = ttk.Combobox(config_frame, textvariable=self.arch_var,
                                        values=["Direct-Mapped", "Fully Associative", "Set-Associative"],
                                        state="readonly", width=18)
        self.arch_combo.grid(row=0, column=1, sticky=tk.W, pady=2)
        self.arch_combo.bind("<<ComboboxSelected>>", self._on_architecture_change)

        # Cache size
        ttk.Label(config_frame, text="Cache Size (bytes):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.cache_size_var = tk.StringVar(value="256")
        self.cache_size_entry = ttk.Entry(config_frame, textvariable=self.cache_size_var, width=20)
        self.cache_size_entry.grid(row=1, column=1, sticky=tk.W, pady=2)

        # Block size
        ttk.Label(config_frame, text="Block Size (bytes):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.block_size_var = tk.StringVar(value="16")
        self.block_size_entry = ttk.Entry(config_frame, textvariable=self.block_size_var, width=20)
        self.block_size_entry.grid(row=2, column=1, sticky=tk.W, pady=2)

        # Associativity
        ttk.Label(config_frame, text="Associativity:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.assoc_var = tk.StringVar(value="4")
        self.assoc_entry = ttk.Entry(config_frame, textvariable=self.assoc_var, width=20)
        self.assoc_entry.grid(row=3, column=1, sticky=tk.W, pady=2)
        self.assoc_label = ttk.Label(config_frame, text="")
        self.assoc_label.grid(row=3, column=2, sticky=tk.W, padx=5)

        # Word size
        ttk.Label(config_frame, text="Word Size (bytes):").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.word_size_var = tk.StringVar(value="4")
        self.word_size_combo = ttk.Combobox(config_frame, textvariable=self.word_size_var,
                                             values=["1", "2", "4", "8"], state="readonly", width=18)
        self.word_size_combo.grid(row=4, column=1, sticky=tk.W, pady=2)

        # Address width
        ttk.Label(config_frame, text="Address Width (bits):").grid(row=5, column=0, sticky=tk.W, pady=2)
        self.addr_width_var = tk.StringVar(value="32")
        self.addr_width_combo = ttk.Combobox(config_frame, textvariable=self.addr_width_var,
                                              values=["16", "32", "64"], state="readonly", width=18)
        self.addr_width_combo.grid(row=5, column=1, sticky=tk.W, pady=2)

        # Replacement policy
        ttk.Label(config_frame, text="Replacement Policy:").grid(row=6, column=0, sticky=tk.W, pady=2)
        self.policy_var = tk.StringVar(value="LRU")
        self.policy_combo = ttk.Combobox(config_frame, textvariable=self.policy_var,
                                          values=["LRU", "FIFO", "Random"], state="readonly", width=18)
        self.policy_combo.grid(row=6, column=1, sticky=tk.W, pady=2)

    def _create_trace_panel(self):
        """Create memory trace input panel."""
        trace_frame = ttk.LabelFrame(self.left_frame, text="Memory Trace", padding="10")
        trace_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Trace input text area
        ttk.Label(trace_frame, text="Enter trace (hex/decimal, one per line):").pack(anchor=tk.W)

        self.trace_text = scrolledtext.ScrolledText(trace_frame, width=35, height=12, font=("Consolas", 9))
        self.trace_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Load default sample
        self.trace_text.insert(tk.END, "# Simple trace example\n")
        self.trace_text.insert(tk.END, "# Format: address [R/W]\n")
        self.trace_text.insert(tk.END, "0x00 R\n0x04 R\n0x08 R\n0x0C R\n")
        self.trace_text.insert(tk.END, "0x10 R\n0x14 R\n0x18 R\n0x1C R\n")
        self.trace_text.insert(tk.END, "0x00 R\n0x04 R\n")

        # Load trace button
        btn_frame = ttk.Frame(trace_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        self.load_trace_btn = ttk.Button(btn_frame, text="Load Trace File", command=self._load_trace_file)
        self.load_trace_btn.pack(side=tk.LEFT, padx=2)

        self.clear_trace_btn = ttk.Button(btn_frame, text="Clear", command=self._clear_trace)
        self.clear_trace_btn.pack(side=tk.LEFT, padx=2)

    def _create_control_panel(self):
        """Create simulation control buttons."""
        control_frame = ttk.LabelFrame(self.left_frame, text="Simulation Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=5)

        btn_frame1 = ttk.Frame(control_frame)
        btn_frame1.pack(fill=tk.X, pady=2)

        self.run_btn = ttk.Button(btn_frame1, text="Run Full Simulation", command=self._run_simulation)
        self.run_btn.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.reset_btn = ttk.Button(btn_frame1, text="Reset", command=self._reset_simulation)
        self.reset_btn.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        btn_frame2 = ttk.Frame(control_frame)
        btn_frame2.pack(fill=tk.X, pady=2)

        self.step_btn = ttk.Button(btn_frame2, text="Step", command=self._step_simulation)
        self.step_btn.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.compare_btn = ttk.Button(btn_frame2, text="Compare Architectures", command=self._compare_architectures)
        self.compare_btn.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

    def _create_amat_panel(self):
        """Create AMAT configuration panel."""
        amat_frame = ttk.LabelFrame(self.left_frame, text="AMAT Parameters", padding="10")
        amat_frame.pack(fill=tk.X, pady=5)

        ttk.Label(amat_frame, text="Hit Time (cycles):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.hit_time_var = tk.StringVar(value="1")
        self.hit_time_entry = ttk.Entry(amat_frame, textvariable=self.hit_time_var, width=10)
        self.hit_time_entry.grid(row=0, column=1, sticky=tk.W, pady=2)

        ttk.Label(amat_frame, text="Miss Penalty (cycles):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.miss_penalty_var = tk.StringVar(value="100")
        self.miss_penalty_entry = ttk.Entry(amat_frame, textvariable=self.miss_penalty_var, width=10)
        self.miss_penalty_entry.grid(row=1, column=1, sticky=tk.W, pady=2)

    def _create_address_viz_panel(self):
        """Create address decomposition visualization panel."""
        addr_frame = ttk.LabelFrame(self.right_frame, text="Address Decomposition", padding="10")
        addr_frame.pack(fill=tk.X, pady=5)

        self.addr_viz_text = tk.Text(addr_frame, height=10, font=("Consolas", 10), state=tk.DISABLED)
        self.addr_viz_text.pack(fill=tk.X)

        # Configure tags for coloring
        self.addr_viz_text.tag_configure("tag_bits", foreground="#e74c3c", font=("Consolas", 10, "bold"))
        self.addr_viz_text.tag_configure("index_bits", foreground="#3498db", font=("Consolas", 10, "bold"))
        self.addr_viz_text.tag_configure("offset_bits", foreground="#27ae60", font=("Consolas", 10, "bold"))
        self.addr_viz_text.tag_configure("header", font=("Consolas", 10, "bold"))
        self.addr_viz_text.tag_configure("hit", foreground="#27ae60", font=("Consolas", 10, "bold"))
        self.addr_viz_text.tag_configure("miss", foreground="#e74c3c", font=("Consolas", 10, "bold"))

    def _create_cache_viz_panel(self):
        """Create cache state visualization panel."""
        cache_frame = ttk.LabelFrame(self.right_frame, text="Cache State", padding="10")
        cache_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Treeview for cache visualization
        columns = ("set", "way0", "way1", "way2", "way3", "way4", "way5", "way6", "way7")
        self.cache_tree = ttk.Treeview(cache_frame, columns=columns, show="headings", height=10)

        self.cache_tree.heading("set", text="Set")
        for i in range(8):
            self.cache_tree.heading(f"way{i}", text=f"Way {i}")
            self.cache_tree.column(f"way{i}", width=80, anchor=tk.CENTER)

        self.cache_tree.column("set", width=50, anchor=tk.CENTER)

        # Scrollbar for treeview
        cache_scroll = ttk.Scrollbar(cache_frame, orient=tk.VERTICAL, command=self.cache_tree.yview)
        self.cache_tree.configure(yscrollcommand=cache_scroll.set)

        self.cache_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        cache_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_log_panel(self):
        """Create access log panel."""
        log_frame = ttk.LabelFrame(self.right_frame, text="Access Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, width=80, height=10, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for log
        self.log_text.tag_configure("hit", foreground="#27ae60")
        self.log_text.tag_configure("miss", foreground="#e74c3c")
        self.log_text.tag_configure("header", font=("Consolas", 9, "bold"))

    def _create_stats_panel(self):
        """Create statistics panel."""
        stats_frame = ttk.LabelFrame(self.right_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=5)

        self.stats_text = tk.Text(stats_frame, height=6, font=("Consolas", 10), state=tk.DISABLED)
        self.stats_text.pack(fill=tk.X)

    def _setup_layout(self):
        """Setup the main layout."""
        self.main_paned.add(self.left_frame, weight=1)
        self.main_paned.add(self.right_frame, weight=3)
        self.main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _on_architecture_change(self, event=None):
        """Handle architecture selection change."""
        arch = self.arch_var.get()

        if arch == "Direct-Mapped":
            self.assoc_entry.config(state=tk.DISABLED)
            self.assoc_var.set("1")
            self.assoc_label.config(text="(fixed)")
            self.policy_combo.config(state=tk.DISABLED)
            self.policy_var.set("N/A")
        elif arch == "Fully Associative":
            self.assoc_entry.config(state=tk.DISABLED)
            try:
                cache_size = int(self.cache_size_var.get())
                block_size = int(self.block_size_var.get())
                num_blocks = cache_size // block_size
                self.assoc_var.set(str(num_blocks))
                self.assoc_label.config(text=f"(= {num_blocks} blocks)")
            except ValueError:
                self.assoc_label.config(text="(= num_blocks)")
            self.policy_combo.config(state="readonly")
        else:  # Set-Associative
            self.assoc_entry.config(state=tk.NORMAL)
            self.assoc_label.config(text="")
            self.policy_combo.config(state="readonly")

    def _load_trace_file(self):
        """Load memory trace from file."""
        filename = filedialog.askopenfilename(
            title="Select Trace File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir="sample_traces"
        )

        if filename:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                self.trace_text.delete(1.0, tk.END)
                self.trace_text.insert(tk.END, content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")

    def _clear_trace(self):
        """Clear the trace input."""
        self.trace_text.delete(1.0, tk.END)

    def _parse_trace(self):
        """Parse the trace text into list of (address, operation) tuples."""
        trace_content = self.trace_text.get(1.0, tk.END)
        accesses = []

        for line in trace_content.strip().split('\n'):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Remove inline comments
            if '#' in line:
                line = line[:line.index('#')].strip()

            parts = line.split()
            if not parts:
                continue

            # Parse address
            addr_str = parts[0]
            try:
                if addr_str.lower().startswith('0x'):
                    address = int(addr_str, 16)
                else:
                    address = int(addr_str)
            except ValueError:
                continue  # Skip invalid lines

            # Parse operation (default to Read)
            operation = 'R'
            if len(parts) > 1:
                op = parts[1].upper()
                if op in ('R', 'W', 'READ', 'WRITE'):
                    operation = op[0]

            accesses.append((address, operation))

        return accesses

    def _create_cache(self):
        """Create cache instance based on current configuration."""
        try:
            cache_size = int(self.cache_size_var.get())
            block_size = int(self.block_size_var.get())
            associativity = int(self.assoc_var.get())
            word_size = int(self.word_size_var.get())
            address_width = int(self.addr_width_var.get())
            replacement_policy = self.policy_var.get()
            architecture = self.arch_var.get()

            # Validation
            if cache_size <= 0 or block_size <= 0:
                raise ValueError("Cache size and block size must be positive")
            if cache_size % block_size != 0:
                raise ValueError("Cache size must be divisible by block size")

            self.cache = create_cache(
                architecture=architecture,
                cache_size=cache_size,
                block_size=block_size,
                associativity=associativity if architecture == "Set-Associative" else None,
                word_size=word_size,
                address_width=address_width,
                replacement_policy=replacement_policy
            )
            return True

        except ValueError as e:
            messagebox.showerror("Configuration Error", str(e))
            return False

    def _run_simulation(self):
        """Run the full simulation."""
        if not self._create_cache():
            return

        self.parsed_trace = self._parse_trace()
        if not self.parsed_trace:
            messagebox.showwarning("Warning", "No valid trace entries found")
            return

        self.cache.reset()
        self.current_access_index = 0

        # Clear displays
        self.log_text.delete(1.0, tk.END)
        self._write_log_header()

        # Run all accesses
        for address, operation in self.parsed_trace:
            result = self.cache.access(address, operation)
            self._log_access(result)
            self.current_access_index += 1

        # Update visualizations
        self._update_cache_viz()
        self._update_stats()

        # Show final address decomposition
        if self.parsed_trace:
            last_result = self.cache.access_history[-1]
            self._update_address_viz(last_result)

    def _step_simulation(self):
        """Step through simulation one access at a time."""
        if self.cache is None or self.current_access_index >= len(self.parsed_trace):
            # Initialize or restart
            if not self._create_cache():
                return

            self.parsed_trace = self._parse_trace()
            if not self.parsed_trace:
                messagebox.showwarning("Warning", "No valid trace entries found")
                return

            self.cache.reset()
            self.current_access_index = 0
            self.log_text.delete(1.0, tk.END)
            self._write_log_header()

        if self.current_access_index < len(self.parsed_trace):
            address, operation = self.parsed_trace[self.current_access_index]
            result = self.cache.access(address, operation)
            self._log_access(result)
            self._update_address_viz(result)
            self._update_cache_viz()
            self._update_stats()
            self.current_access_index += 1

            if self.current_access_index >= len(self.parsed_trace):
                self.log_text.insert(tk.END, "\n--- Simulation Complete ---\n")

    def _reset_simulation(self):
        """Reset the simulation."""
        if self.cache:
            self.cache.reset()
        self.current_access_index = 0
        self.parsed_trace = []

        # Clear displays
        self.log_text.delete(1.0, tk.END)

        self.addr_viz_text.config(state=tk.NORMAL)
        self.addr_viz_text.delete(1.0, tk.END)
        self.addr_viz_text.config(state=tk.DISABLED)

        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.config(state=tk.DISABLED)

        for item in self.cache_tree.get_children():
            self.cache_tree.delete(item)

    def _write_log_header(self):
        """Write header to log."""
        header = f"{'#':<4} {'Address':<12} {'Op':<3} {'Tag':<12} {'Index':<6} {'Offset':<6} {'Result':<8}\n"
        header += "-" * 60 + "\n"
        self.log_text.insert(tk.END, header, "header")

    def _log_access(self, result):
        """Log a cache access result."""
        idx = len(self.cache.access_history)
        hit_miss = "HIT" if result['hit'] else "MISS"
        tag = "miss" if not result['hit'] else "hit"

        line = f"{idx:<4} 0x{result['address']:08X}  {result['operation']:<3} "
        line += f"0x{result['tag']:08X}  {result['index']:<6} {result['offset']:<6} "

        self.log_text.insert(tk.END, line)
        self.log_text.insert(tk.END, f"{hit_miss:<8}\n", tag)

        # Auto-scroll to bottom
        self.log_text.see(tk.END)

    def _update_address_viz(self, result):
        """Update address decomposition visualization."""
        self.addr_viz_text.config(state=tk.NORMAL)
        self.addr_viz_text.delete(1.0, tk.END)

        decomp = result['decomposition']
        breakdown = decomp['breakdown']

        # Address header
        self.addr_viz_text.insert(tk.END, f"Address: 0x{result['address']:08X} ({result['address']})\n", "header")

        # Binary representation with color coding
        binary = decomp['binary']
        tag_bits = breakdown['tag']['num_bits']
        index_bits = breakdown['index']['num_bits']
        offset_bits = breakdown['offset']['num_bits']

        self.addr_viz_text.insert(tk.END, "Binary:  ")

        # Insert colored bit groups
        if tag_bits > 0:
            self.addr_viz_text.insert(tk.END, binary[:tag_bits], "tag_bits")
        if index_bits > 0:
            self.addr_viz_text.insert(tk.END, binary[tag_bits:tag_bits+index_bits], "index_bits")
        if offset_bits > 0:
            self.addr_viz_text.insert(tk.END, binary[tag_bits+index_bits:], "offset_bits")

        self.addr_viz_text.insert(tk.END, "\n")

        # Bit range labels
        self.addr_viz_text.insert(tk.END, "         ")
        self.addr_viz_text.insert(tk.END, "|" + "-"*(tag_bits-2) + "TAG" + "-"*(max(0,tag_bits-5)) + "|" if tag_bits > 3 else "", "tag_bits")
        self.addr_viz_text.insert(tk.END, "IDX" if index_bits > 2 else ("I" if index_bits > 0 else ""), "index_bits")
        self.addr_viz_text.insert(tk.END, "|OFF|" if offset_bits > 3 else ("O" if offset_bits > 0 else ""), "offset_bits")
        self.addr_viz_text.insert(tk.END, "\n\n")

        # Detailed breakdown
        self.addr_viz_text.insert(tk.END, "Tag:     ", "tag_bits")
        self.addr_viz_text.insert(tk.END, f"{breakdown['tag']['bits']:<20} ")
        self.addr_viz_text.insert(tk.END, f"= {breakdown['tag']['value']:<8} (0x{breakdown['tag']['value']:X})\n")
        self.addr_viz_text.insert(tk.END, f"         Range: {breakdown['tag']['range']}, Bits: {tag_bits}\n")

        self.addr_viz_text.insert(tk.END, "Index:   ", "index_bits")
        self.addr_viz_text.insert(tk.END, f"{breakdown['index']['bits']:<20} ")
        self.addr_viz_text.insert(tk.END, f"= {breakdown['index']['value']:<8}\n")
        self.addr_viz_text.insert(tk.END, f"         Range: {breakdown['index']['range']}, Bits: {index_bits}\n")

        self.addr_viz_text.insert(tk.END, "Offset:  ", "offset_bits")
        self.addr_viz_text.insert(tk.END, f"{breakdown['offset']['bits']:<20} ")
        self.addr_viz_text.insert(tk.END, f"= {breakdown['offset']['value']:<8}\n")
        self.addr_viz_text.insert(tk.END, f"         Range: {breakdown['offset']['range']}, Bits: {offset_bits}\n\n")

        # Hit/Miss result
        if result['hit']:
            self.addr_viz_text.insert(tk.END, "Result: HIT", "hit")
        else:
            self.addr_viz_text.insert(tk.END, "Result: MISS", "miss")
            if result.get('evicted_tag') is not None:
                self.addr_viz_text.insert(tk.END, f" (evicted tag: 0x{result['evicted_tag']:X})")

        self.addr_viz_text.config(state=tk.DISABLED)

    def _update_cache_viz(self):
        """Update cache state visualization."""
        if not self.cache:
            return

        # Clear existing items
        for item in self.cache_tree.get_children():
            self.cache_tree.delete(item)

        state = self.cache.get_cache_state()
        num_sets = state['num_sets']
        associativity = state['associativity']

        # Update column headers based on associativity
        visible_ways = min(associativity, 8)
        for i in range(8):
            if i < visible_ways:
                self.cache_tree.heading(f"way{i}", text=f"Way {i}")
                self.cache_tree.column(f"way{i}", width=100)
            else:
                self.cache_tree.heading(f"way{i}", text="")
                self.cache_tree.column(f"way{i}", width=0)

        # Build cache display
        lines_by_set = {}
        for line in state['lines']:
            set_idx = line['set']
            if set_idx not in lines_by_set:
                lines_by_set[set_idx] = {}
            lines_by_set[set_idx][line['way']] = line

        for set_idx in range(num_sets):
            values = [f"Set {set_idx}"]
            for way in range(visible_ways):
                if set_idx in lines_by_set and way in lines_by_set[set_idx]:
                    line = lines_by_set[set_idx][way]
                    if line['valid']:
                        values.append(line['tag_hex'])
                    else:
                        values.append("---")
                else:
                    values.append("---")

            # Pad remaining columns
            while len(values) < 9:
                values.append("")

            self.cache_tree.insert("", tk.END, values=values)

    def _update_stats(self):
        """Update statistics display."""
        if not self.cache:
            return

        stats = self.cache.get_statistics()
        config = self.cache.get_config()

        try:
            hit_time = float(self.hit_time_var.get())
            miss_penalty = float(self.miss_penalty_var.get())
        except ValueError:
            hit_time = 1
            miss_penalty = 100

        amat = self.cache.calculate_amat(hit_time, miss_penalty)

        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)

        text = f"Architecture: {config['replacement_policy']} {self.arch_var.get()}\n"
        text += f"Sets: {config['num_sets']}, Associativity: {config['associativity']}, "
        text += f"Blocks: {config['num_blocks']}\n"
        text += f"Bit allocation: Tag={config['tag_bits']}, Index={config['index_bits']}, Offset={config['offset_bits']}\n"
        text += f"\n"
        text += f"Hits: {stats['hits']}, Misses: {stats['misses']}, Total: {stats['total_accesses']}\n"
        text += f"Hit Rate: {stats['hit_rate']:.2f}%, Miss Rate: {stats['miss_rate']:.2f}%\n"
        text += f"AMAT: {amat['formula']}\n"

        self.stats_text.insert(tk.END, text)
        self.stats_text.config(state=tk.DISABLED)

    def _compare_architectures(self):
        """Compare all three architectures side by side."""
        self.parsed_trace = self._parse_trace()
        if not self.parsed_trace:
            messagebox.showwarning("Warning", "No valid trace entries found")
            return

        try:
            cache_size = int(self.cache_size_var.get())
            block_size = int(self.block_size_var.get())
            word_size = int(self.word_size_var.get())
            address_width = int(self.addr_width_var.get())
            hit_time = float(self.hit_time_var.get())
            miss_penalty = float(self.miss_penalty_var.get())
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid configuration: {e}")
            return

        # Create comparison window
        compare_win = tk.Toplevel(self.master)
        compare_win.title("Architecture Comparison")
        compare_win.geometry("900x500")

        # Create caches - use user's configured associativity for set-associative comparison
        user_assoc = int(self.assoc_var.get())
        architectures = [
            ("Direct-Mapped", create_cache("Direct-Mapped", cache_size, block_size,
                                           word_size=word_size, address_width=address_width)),
            ("Fully Associative", create_cache("Fully Associative", cache_size, block_size,
                                               word_size=word_size, address_width=address_width,
                                               replacement_policy="LRU")),
            (f"{user_assoc}-way Set-Associative", create_cache("Set-Associative", cache_size, block_size,
                                                    associativity=user_assoc, word_size=word_size,
                                                    address_width=address_width,
                                                    replacement_policy="LRU"))
        ]

        # Run trace on each
        results = []
        for name, cache in architectures:
            for address, operation in self.parsed_trace:
                cache.access(address, operation)
            stats = cache.get_statistics()
            amat = cache.calculate_amat(hit_time, miss_penalty)
            results.append((name, stats, amat))

        # Display results
        ttk.Label(compare_win, text="Architecture Comparison Results",
                  font=("Arial", 14, "bold")).pack(pady=10)

        # Create comparison table
        columns = ("arch", "hits", "misses", "hit_rate", "miss_rate", "amat")
        tree = ttk.Treeview(compare_win, columns=columns, show="headings", height=5)

        tree.heading("arch", text="Architecture")
        tree.heading("hits", text="Hits")
        tree.heading("misses", text="Misses")
        tree.heading("hit_rate", text="Hit Rate")
        tree.heading("miss_rate", text="Miss Rate")
        tree.heading("amat", text="AMAT")

        tree.column("arch", width=200)
        tree.column("hits", width=80, anchor=tk.CENTER)
        tree.column("misses", width=80, anchor=tk.CENTER)
        tree.column("hit_rate", width=100, anchor=tk.CENTER)
        tree.column("miss_rate", width=100, anchor=tk.CENTER)
        tree.column("amat", width=120, anchor=tk.CENTER)

        # Find best performer
        best_hit_rate = max(r[1]['hit_rate'] for r in results)

        for name, stats, amat in results:
            hit_rate_str = f"{stats['hit_rate']:.2f}%"
            if stats['hit_rate'] == best_hit_rate:
                hit_rate_str += " *"  # Mark best

            tree.insert("", tk.END, values=(
                name,
                stats['hits'],
                stats['misses'],
                hit_rate_str,
                f"{stats['miss_rate']:.2f}%",
                f"{amat['amat']:.2f} cycles"
            ))

        tree.pack(padx=20, pady=10, fill=tk.X)

        # Analysis text
        analysis_frame = ttk.LabelFrame(compare_win, text="Analysis", padding="10")
        analysis_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        analysis = tk.Text(analysis_frame, height=12, font=("Consolas", 10))
        analysis.pack(fill=tk.BOTH, expand=True)

        analysis_text = f"Trace: {len(self.parsed_trace)} memory accesses\n"
        analysis_text += f"Cache: {cache_size} bytes, {block_size}-byte blocks\n\n"

        analysis_text += "Key Observations:\n"

        dm_stats = results[0][1]
        fa_stats = results[1][1]
        sa_stats = results[2][1]

        if fa_stats['hits'] > dm_stats['hits']:
            diff = fa_stats['hits'] - dm_stats['hits']
            analysis_text += f"- Fully Associative has {diff} more hits than Direct-Mapped\n"
            analysis_text += "  (Indicates conflict misses in Direct-Mapped cache)\n"

        if sa_stats['hit_rate'] >= dm_stats['hit_rate'] and sa_stats['hit_rate'] <= fa_stats['hit_rate']:
            analysis_text += "- Set-Associative provides a middle ground between DM and FA\n"

        analysis_text += f"\nAMAT Formula: Hit Time + (Miss Rate x Miss Penalty)\n"
        analysis_text += f"             = {hit_time} + (Miss Rate x {miss_penalty})\n"

        analysis.insert(tk.END, analysis_text)
        analysis.config(state=tk.DISABLED)

        # Close button
        ttk.Button(compare_win, text="Close", command=compare_win.destroy).pack(pady=10)
