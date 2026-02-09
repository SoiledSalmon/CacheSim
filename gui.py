# gui.py
import tkinter as tk
from tkinter import scrolledtext
from cache_simulator import CacheSimulator

class CacheSimulatorGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Cache Simulator")
        self.log_text = scrolledtext.ScrolledText(master, width=100, height=20)
        self.log_text.pack(padx=10, pady=10)
        self.cache_size_entry = tk.Entry(master, width=10)
        self.cache_size_label = tk.Label(master, text="Cache Size:")
        self.cache_size_label.pack()
        self.cache_size_entry.pack()
        self.block_size_entry = tk.Entry(master, width=10)
        self.block_size_label = tk.Label(master, text="Block Size:")
        self.block_size_label.pack()
        self.block_size_entry.pack()
        self.associativity_entry = tk.Entry(master, width=10)
        self.associativity_label = tk.Label(master, text="Associativity:")
        self.associativity_label.pack()
        self.associativity_entry.pack()
        self.run_simulation_button = tk.Button(master, text="Run Simulation", command=self.run_simulation)
        self.run_simulation_button.pack(pady=5)
        self.update_stats_button = tk.Button(master, text="Update Statistics", command=self.update_stats)
        self.update_stats_button.pack(pady=5)

    def run_simulation(self):
        cache_size = int(self.cache_size_entry.get())
        block_size = int(self.block_size_entry.get())
        associativity = int(self.associativity_entry.get())
        self.cache_simulator = CacheSimulator(cache_size, block_size, associativity)
        memory_accesses = [
            (0x0A, "R"),
            (0x0B, "R"),
            (0x0C, "R"),
            (0x0D, "R"),
            (0x0E, "R"),
            (0x0F, "R"),
            (0x10, "R"),
            (0x11, "R"),
            (0x12, "R"),
            (0x13, "R"),
            (0x14, "R"),
        ]
        self.log_text.delete(1.0, tk.END)
        self.cache_simulator.simulate_memory_accesses(memory_accesses, self.log_text)

    def update_stats(self):
        self.log_text.delete(1.0, tk.END)
        self.cache_simulator.print_stats(self.log_text)
