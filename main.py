# main.py
import tkinter as tk
from gui import CacheSimulatorGUI

if __name__ == "__main__":
    root = tk.Tk()
    gui = CacheSimulatorGUI(root)
    root.mainloop()
