import tkinter as tk
from tkinter import ttk

class ProgressIndicator:
    def __init__(self, parent):
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

    def update_progress(self, value):
        self.progress_var.set(value)
        self.progress_bar.update_idletasks()