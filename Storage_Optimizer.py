import os
import tkinter as tk
from tkinter import ttk, messagebox
import shutil
from pathlib import Path
import sys
from typing import List, Dict, Tuple
import threading
import time
from datetime import datetime
import json
import humanize
from tkinter import filedialog
import platform
import psutil

class EnhancedDiskSpaceAnalyzer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Educational Disk Space Analyzer")
        self.root.geometry("1400x900")
        
        # Updated educational color scheme
        self.bg_color = "#003B36"  # Dark teal background
        self.fg_color = "#FFFFFF"  # White text
        self.accent_color = "#004D40"  # Darker teal for contrast
        self.highlight_color = "#00897B"  # Lighter teal for highlights
        self.button_color = "#FFD700"  # Golden yellow for buttons
        self.error_color = "#B71C1C"  # Ruby red for warnings/errors
        self.success_color = "#2E7D32"  # Green for success indicators
        self.header_color = "#81C784"  # Light green for headers
        
        # State variables
        self.scanning = False
        self.total_files = 0
        self.scanned_files = 0
        self.last_scan_time = None
        self.scan_history = []
        
        # Load saved settings
        self.settings = self.load_settings()
        
        # Configure enhanced dark theme
        self.root.configure(bg=self.bg_color)
        self.style = ttk.Style()
        self.style.theme_create("enhanced_dark", parent="alt", settings={
            "TNotebook": {"configure": {"background": self.bg_color}},
            "TNotebook.Tab": {
                "configure": {"background": self.accent_color, "foreground": self.fg_color, "padding": [10, 2]},
                "map": {"background": [("selected", self.highlight_color)]}
            },
            "Treeview": {
                "configure": {
                    "background": self.bg_color,
                    "foreground": self.fg_color,
                    "fieldbackground": self.bg_color,
                    "rowheight": 25
                }
            }
        })
        self.style.theme_use("enhanced_dark")
        
        self.setup_ui()
        self.setup_menu()
        self.setup_context_menu()
        
    def setup_menu(self):
        menubar = tk.Menu(self.root, bg=self.accent_color, fg=self.fg_color)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.accent_color, fg=self.fg_color)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results...", command=self.export_results)
        file_menu.add_command(label="Import Results...", command=self.import_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg=self.accent_color, fg=self.fg_color)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh", command=self.refresh_view)
        view_menu.add_command(label="Clear Results", command=self.clear_results)
        
    def setup_ui(self):
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Scanner tab
        self.scanner_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.scanner_frame, text="Scanner")
        
        # Drive info and selection
        self.setup_drive_frame()
        
        # Advanced filters
        self.setup_filter_frame()
        
        # Progress frame
        self.setup_progress_frame()
        
        # Results treeview
        self.setup_results_frame()
        
        # Statistics tab
        self.stats_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.stats_frame, text="Statistics")
        self.setup_statistics()
        
    def setup_drive_frame(self):
        self.drive_frame = tk.LabelFrame(self.scanner_frame, 
                                       text="Drive Selection", 
                                       bg=self.bg_color,
                                       fg=self.header_color,
                                       font=("Arial", 10, "bold"))
        self.drive_frame.pack(pady=10, padx=10, fill="x")
        
        # Drive selection
        tk.Label(self.drive_frame,
                text="Select Drive:",
                bg=self.bg_color,
                fg=self.fg_color,
                font=("Arial", 10)).pack(side="left", padx=5)
        
        self.drive_var = tk.StringVar()
        self.drives = self.get_drives_with_info()
        self.drive_menu = ttk.Combobox(self.drive_frame,
                                     textvariable=self.drive_var,
                                     values=[f"{d['name']} ({d['free_space']} free)" for d in self.drives],
                                     width=30)
        self.drive_menu.pack(side="left", padx=5)
        
        # Updated scan button with new styling
        self.scan_button = tk.Button(
            self.drive_frame,
            text="Scan Drive",
            command=self.start_scan,
            bg=self.button_color,
            fg=self.bg_color,
            font=("Arial", 10, "bold"),
            relief="raised",
            padx=15,
            pady=5,
            cursor="hand2"
        )
        self.scan_button.pack(side="left", padx=5)
        
        # Updated stop button with new styling
        self.stop_button = tk.Button(
            self.drive_frame,
            text="Stop Scan",
            command=self.stop_scan,
            bg=self.error_color,
            fg=self.fg_color,
            font=("Arial", 10, "bold"),
            relief="raised",
            padx=15,
            pady=5,
            cursor="hand2",
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=5)
        
    def setup_filter_frame(self):
        self.filter_frame = tk.LabelFrame(
            self.scanner_frame,
            text="Filters",
            bg=self.bg_color,
            fg=self.header_color,
            font=("Arial", 10, "bold")
        )
        self.filter_frame.pack(pady=5, padx=10, fill="x")
        
        # Updated filter labels and entries with new styling
        filter_label = tk.Label(
            self.filter_frame,
            text="File extensions (comma-separated):",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10)
        )
        filter_label.pack(side="left", padx=5)
        
        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(
            self.filter_frame,
            textvariable=self.filter_var,
            bg=self.accent_color,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            width=30,
            font=("Arial", 10)
        )
        self.filter_entry.pack(side="left", padx=5)
        
        # Size filter with new styling
        size_label = tk.Label(
            self.filter_frame,
            text="Minimum size (MB):",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 10)
        )
        size_label.pack(side="left", padx=5)
        
        self.size_var = tk.StringVar(value="0")
        self.size_entry = tk.Entry(
            self.filter_frame,
            textvariable=self.size_var,
            bg=self.accent_color,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            width=10,
            font=("Arial", 10)
        )
        self.size_entry.pack(side="left", padx=5)
        
        # Date filter
        self.date_var = tk.BooleanVar()
        self.date_check = tk.Checkbutton(self.filter_frame,
                                       text="Modified in last 30 days",
                                       variable=self.date_var,
                                       bg=self.bg_color,
                                       fg=self.fg_color,
                                       selectcolor=self.accent_color)
        self.date_check.pack(side="left", padx=5)
        
    def setup_progress_frame(self):
        """Enhanced progress frame with better visual feedback"""
        self.progress_frame = tk.Frame(self.scanner_frame, bg=self.bg_color)
        self.progress_frame.pack(pady=5, padx=10, fill="x")
        
        # Progress bar style
        self.style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=self.bg_color,
            background=self.success_color,
            darkcolor=self.success_color,
            lightcolor=self.success_color,
            bordercolor=self.bg_color,
            thickness=20
        )
        
        # Progress bar frame
        progress_container = tk.Frame(self.progress_frame, bg=self.bg_color)
        progress_container.pack(fill="x", padx=5)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_container,
            variable=self.progress_var,
            mode="determinate",
            style="Custom.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(fill="x", side="left", expand=True)
        
        # Percentage label
        self.percentage_label = tk.Label(
            progress_container,
            text="0%",
            bg=self.bg_color,
            fg=self.success_color,
            font=("Arial", 10, "bold"),
            width=6
        )
        self.percentage_label.pack(side="left", padx=(5, 0))
        
        # Status label with more details
        self.status_label = tk.Label(
            self.progress_frame,
            text="Ready to scan",
            bg=self.bg_color,
            fg=self.header_color,
            font=("Arial", 10, "bold")
        )
        self.status_label.pack(pady=5)
        
        # Bind progress updates to percentage label
        self.progress_var.trace_add("write", self.update_percentage_label)
    
    def setup_results_frame(self):
        self.tree_frame = tk.Frame(self.scanner_frame, bg=self.bg_color)
        self.tree_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        # Enhanced Treeview
        self.tree = ttk.Treeview(self.tree_frame,
                                columns=("Size", "Type", "Modified", "Path"),
                                show="headings",
                                selectmode="extended")
        
        self.tree.heading("Size", text="Size", command=lambda: self.sort_tree("Size"))
        self.tree.heading("Type", text="Type", command=lambda: self.sort_tree("Type"))
        self.tree.heading("Modified", text="Modified", command=lambda: self.sort_tree("Modified"))
        self.tree.heading("Path", text="Path", command=lambda: self.sort_tree("Path"))
        
        self.tree.column("Size", width=100)
        self.tree.column("Type", width=100)
        self.tree.column("Modified", width=150)
        self.tree.column("Path", width=500)
        
        # Scrollbars
        vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.tree.grid(column=0, row=0, sticky="nsew")
        vsb.grid(column=1, row=0, sticky="ns")
        hsb.grid(column=0, row=1, sticky="ew")
        
        self.tree_frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)
        
    def setup_statistics(self):
        self.stats_canvas = tk.Canvas(self.stats_frame, bg=self.bg_color)
        self.stats_canvas.pack(fill="both", expand=True)
        
        # Statistics will be updated after scan
        self.stats_labels = {}
        
    def setup_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0, bg=self.accent_color, fg=self.fg_color)
        self.context_menu.add_command(label="Open File", command=self.open_file)
        self.context_menu.add_command(label="Open Containing Folder", command=self.open_folder)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete File", command=self.delete_file)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
        
    def get_drives_with_info(self) -> List[Dict]:
        drives = []
        if sys.platform == "win32":
            for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive_path = f"{d}:\\"
                if os.path.exists(drive_path):
                    try:
                        usage = shutil.disk_usage(drive_path)
                        drives.append({
                            "name": drive_path,
                            "total_space": humanize.naturalsize(usage.total),
                            "free_space": humanize.naturalsize(usage.free)
                        })
                    except:
                        continue
        else:
            usage = shutil.disk_usage("/")
            drives.append({
                "name": "/",
                "total_space": humanize.naturalsize(usage.total),
                "free_space": humanize.naturalsize(usage.free)
            })
        return drives
    
    def is_system_file(self, path: str) -> bool:
        system_paths = {
            "Windows", "Program Files", "Program Files (x86)",
            "ProgramData", "$Recycle.Bin", "System Volume Information",
            "AppData", "Recovery"
        }
        return any(sp in path for sp in system_paths)
    
    def scan_directory(self):
        """Enhanced scan functionality with visible progress"""
        try:
            self.scanning = True
            self.tree.delete(*self.tree.get_children())
            
            # Extract drive letter/path from selection
            drive_selection = self.drive_var.get().split()[0]
            
            if not os.path.exists(drive_selection):
                messagebox.showerror("Error", "Selected drive is not accessible!")
                self.stop_scan()
                return
            
            # Reset counters and update UI
            self.total_files = 0
            self.scanned_files = 0
            self.progress_var.set(0)
            
            # Initialize counting progress
            self.status_label.config(text="Phase 1/2: Counting files...")
            self.root.update()
            
            # Count files with progress updates
            total_dirs = sum(1 for _ in os.walk(drive_selection))
            dirs_checked = 0
            
            for _, _, files in os.walk(drive_selection):
                if not self.scanning:
                    return
                
                self.total_files += len(files)
                dirs_checked += 1
                
                # Update counting progress
                counting_progress = (dirs_checked / total_dirs) * 50  # First 50% for counting
                self.progress_var.set(counting_progress)
                self.status_label.config(
                    text=f"Phase 1/2: Counting files... {counting_progress:.1f}% ({self.total_files:,} files found)"
                )
                self.root.update()
            
            # Now perform the actual scan
            self.status_label.config(text="Phase 2/2: Scanning files...")
            self.root.update()
            
            for root, _, files in os.walk(drive_selection):
                if not self.scanning:
                    return
                    
                if self.is_system_file(root):
                    continue
                    
                for file in files:
                    if not self.scanning:
                        return
                        
                    try:
                        file_path = os.path.join(root, file)
                        if self.is_system_file(file_path):
                            continue
                            
                        # Get file information
                        stats = os.stat(file_path)
                        file_size = stats.st_size
                        file_type = os.path.splitext(file)[1].lower() or "No extension"
                        modified_time = datetime.fromtimestamp(stats.st_mtime)
                        
                        # Apply filters
                        if not self.apply_filters(file_type, file_size/(1024*1024), modified_time):
                            continue
                            
                        # Insert into tree
                        self.tree.insert("", "end", values=(
                            humanize.naturalsize(file_size),
                            file_type,
                            modified_time.strftime("%Y-%m-%d %H:%M:%S"),
                            file_path
                        ))
                        
                        self.scanned_files += 1
                        
                        # Update scanning progress (50-100%)
                        if self.total_files > 0:
                            scan_progress = 50 + (self.scanned_files / self.total_files) * 50
                            self.progress_var.set(scan_progress)
                            self.status_label.config(
                                text=f"Phase 2/2: Scanning files... {scan_progress:.1f}% ({self.scanned_files:,}/{self.total_files:,})"
                            )
                            self.root.update()
                            
                    except (PermissionError, OSError) as e:
                        continue
            
            self.update_statistics()
            
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during scanning: {str(e)}")
        finally:
            self.scanning = False
            self.status_label.config(
                text=f"Scan complete - {self.scanned_files:,} files processed"
            )
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress_var.set(100)
    
    def apply_filters(self, file_type: str, file_size: float, modified_time: datetime) -> bool:
        # Extension filter
        if self.filter_var.get():
            extensions = [ext.strip().lower() for ext in self.filter_var.get().split(",")]
            if not any(file_type.endswith(ext) for ext in extensions):
                return False
        
        # Size filter
        try:
            min_size = float(self.size_var.get())
            if file_size < min_size:
                return False
        except ValueError:
            pass
        
        # Date filter
        if self.date_var.get():
            days_old = (datetime.now() - modified_time).days
            if days_old > 30:
                return False
        
        return True
    
    def update_progress(self):
        """Update progress bar and labels"""
        if self.total_files > 0:
            progress = (self.scanned_files / self.total_files) * 100
            self.progress_var.set(progress)
            self.status_label.config(
                text=f"Scanning... {self.scanned_files:,} / {self.total_files:,} files"
            )
            self.root.update_idletasks()
    
    def update_statistics(self):
        # Clear existing statistics
        for widget in self.stats_frame.winfo_children():
            widget.destroy()
        
        # Calculate statistics
        total_size = 0
        file_types = {}
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            size_str = values[0]
            file_type = values[1]
            
            # Convert size string to bytes
            size = humanize.parse_size(size_str)
            total_size += size
            
            file_types[file_type] = file_types.get(file_type, 0) + 1
        
        # Display statistics
        stats_text = f"""
        Scan Summary:
        -------------
        Total Files: {len(self.tree.get_children()):,}
        Total Size: {humanize.naturalsize(total_size)}
        Scan Time: {self.last_scan_time.strftime('%Y-%m-%d %H:%M:%S')}
        
        File Types:
        -----------
        """
        
        for file_type, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
            stats_text += f"{file_type}: {count:,} files\n"
        
        stats_label = tk.Label(self.stats_frame,
                             text=stats_text,
                             bg=self.bg_color,
                             fg=self.fg_color,
                             justify="left",
                             font=("Courier", 10))
        stats_label.pack(padx=20, pady=20, anchor="w")
    
    def start_scan(self):
        if not self.drive_var.get():
            messagebox.showwarning("Warning", "Please select a drive first!")
            return
        
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        
        scan_thread = threading.Thread(target=self.scan_directory)
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        self.scanning = False
        self.stop_button.config(state="disabled")
        self.status_label.config(text="Scan stopped by user")
        self.scan_button.config(state="normal")
    
    def sort_tree(self, col):
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children("")]
        
        # Custom sorting for size column
        if col == "Size":
            items = [(humanize.parse_size(size), item) for size, item in items]
        
        items.sort(reverse=True)
        
        for index, (_, item) in enumerate(items):
            self.tree.move(item, "", index)
    
    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def open_file(self):
        selected = self.tree.selection()
        if selected:
            file_path = self.tree.item(selected[0])["values"][3]
            os.startfile(file_path) if sys.platform == "win32" else os.system(f"xdg-open '{file_path}'")
    
    def open_folder(self):
        selected = self.tree.selection()
        if selected:
            file_path = self.tree.item(selected[0])["values"][3]
            folder_path = os.path.dirname(file_path)
            os.startfile(folder_path) if sys.platform == "win32" else os.system(f"xdg-open '{folder_path}'")
    
    def delete_file(self):
        selected = self.tree.selection()
        if selected:
            if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected file(s)?"):
                for item in selected:
                    file_path = self.tree.item(item)["values"][3]
                    try:
                        os.remove(file_path)
                        self.tree.delete(item)
                    except OSError as e:
                        messagebox.showerror("Error", f"Could not delete {file_path}\nError: {e}")
    
    def export_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if file_path:
            data = []
            for item in self.tree.get_children():
                values = self.tree.item(item)["values"]
                data.append({
                    "size": values[0],
                    "type": values[1],
                    "modified": values[2],
                    "path": values[3]
                })
            
            with open(file_path, "w") as f:
                json.dump(data, f, indent=2)
    
    def import_results(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json")]
        )
        if file_path:
            with open(file_path, "r") as f:
                data = json.load(f)
            
            self.tree.delete(*self.tree.get_children())
            for item in data:
                self.tree.insert("", "end", values=(
                    item["size"],
                    item["type"],
                    item["modified"],
                    item["path"]
                ))
    
    def refresh_view(self):
        self.start_scan()
    
    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.progress_var.set(0)
        self.status_label.config(text="Ready to scan")
    
    def load_settings(self) -> Dict:
        try:
            with open("analyzer_settings.json", "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def save_settings(self):
        settings = {
            "window_size": self.root.geometry(),
            "last_drive": self.drive_var.get(),
            "last_filter": self.filter_var.get(),
            "min_size": self.size_var.get()
        }
        with open("analyzer_settings.json", "w") as f:
            json.dump(settings, f)
    
    def run(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        self.save_settings()
        self.root.destroy()
    
    def update_percentage_label(self, *args):
        """Update the percentage label when progress changes"""
        progress = self.progress_var.get()
        self.percentage_label.config(text=f"{progress:.1f}%")
        
        # Update color based on progress
        if progress < 33:
            color = self.error_color
        elif progress < 66:
            color = self.button_color
        else:
            color = self.success_color
        
        self.percentage_label.config(fg=color)

if __name__ == "__main__":
    app = EnhancedDiskSpaceAnalyzer()
    app.run()
