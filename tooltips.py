import tkinter as tk

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = tk.Toplevel(widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry("+0+0")
        label = tk.Label(self.tooltip, text=text, background="yellow", relief=tk.SOLID, borderwidth=1, wraplength=150)
        label.pack()
        self.tooltip.withdraw()
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip.wm_geometry(f"+{x}+{y}")
        self.tooltip.deiconify()

    def leave(self, event):
        self.tooltip.withdraw()