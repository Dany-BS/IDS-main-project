import customtkinter as ctk
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from tkinter import messagebox
import time

class FileMonitorHandler(FileSystemEventHandler):
    def __init__(self, window):
        super().__init__()
        self.window = window
        self.current_operations = set()  # Track current operations
        self.pending_renames = {}  # Track pending rename operations
        self.denied_files = set()  # Track files we've denied creation for
        self.recreated_files = set()  # Track files recreated after denied deletion

    def process_create_event(self, event):
        """Handle creation events specifically"""
        path = event.src_path
            
        # Skip if currently processing this path
        if path in self.current_operations:
            return
            
        # Skip if temporary file
        if path.endswith('.tmp'):
            return
            
        name = os.path.basename(path)
        
        # Skip system files
        if name.startswith('.') or name.startswith('~') or name.startswith('$'):
            return

        # Skip if this is a file being recreated after denied deletion
        if path in self.recreated_files:
            self.recreated_files.discard(path)
            self.window.log_event(f"🔄 File restored: {name}")
            return
                
        try:
            self.current_operations.add(path)
            
            # Wait briefly to catch any immediate rename
            time.sleep(0.1)
            
            # Check if the file was renamed
            if path in self.pending_renames:
                actual_path = self.pending_renames[path]
                name = os.path.basename(actual_path)
                self.pending_renames.pop(path)
            else:
                actual_path = path
            
            message = f"Allow creation of {name}?"
            allow = self.window.ask_permission(message)
            
            if allow:
                self.window.log_event(f"✅ Allowed creation: {name}")
            else:
                try:
                    # Delete the file without asking again
                    delete_path = actual_path
                    if os.path.exists(delete_path):
                        # Mark this path as one we're deleting due to denied creation
                        self.denied_files.add(delete_path)
                        if event.is_directory:
                            os.rmdir(delete_path)
                        else:
                            os.remove(delete_path)
                    self.window.log_event(f"🚫 Blocked creation: {name}")
                except Exception as e:
                    self.window.log_event(f"❌ Error deleting file: {str(e)}")
        except Exception as e:
            self.window.log_event(f"❌ Error processing creation: {str(e)}")
        finally:
            self.current_operations.discard(path)

    def on_created(self, event):
        """Handle creation events"""
        self.process_create_event(event)

    def on_deleted(self, event):
        """Handle deletion events"""
        path = event.src_path
        
        # Skip if this is a file we deleted due to denied creation
        if path in self.denied_files:
            self.denied_files.discard(path)
            return
            
        # Skip if currently processing this path
        if path in self.current_operations:
            return
            
        # Skip temporary files
        if path.endswith('.tmp'):
            return
            
        name = os.path.basename(path)
        
        # Skip system files and temporary system files
        if name.startswith('.') or name.startswith('~') or name.startswith('$'):
            return
            
        try:
            self.current_operations.add(path)
            type_str = "folder" if event.is_directory else "file"
            message = f"Want to delete {type_str} '{name}'?"
            allow = self.window.ask_permission(message)
            
            if allow:
                self.window.log_event(f"✅ {type_str.capitalize()} deleted: {name}")
            else:
                # Prevent the deletion without any additional prompts
                if event.is_directory:
                    if not os.path.exists(path):
                        os.makedirs(path)  # Recreate the folder if it was deleted
                        self.recreated_files.add(path)
                else:
                    if not os.path.exists(path):
                        # Mark this file as being recreated to avoid showing creation dialog
                        self.recreated_files.add(path)
                        open(path, 'a').close()  # Recreate the file if it was deleted
                self.window.log_event(f"🚫 {type_str.capitalize()} not deleted: {name}")
        finally:
            self.current_operations.discard(path)

    def on_moved(self, event):
        """Handle move/rename events"""
        src_path = event.src_path
        dest_path = event.dest_path
        
        # If this is a rename during creation, store the new path
        if src_path in self.current_operations:
            self.pending_renames[src_path] = dest_path
        
        # For other moves/renames, just allow them
        pass

    def on_modified(self, event):
        """Ignore modification events"""
        pass

class FileManagementWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        self.monitored_paths = []
        self.observers = []
        self.setup_ui()
        
    def setup_ui(self):
        # Create main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=20, pady=20)

        # Add back button at the top
        back_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        back_frame.pack(fill="x", pady=(0, 10))
        
        back_btn = ctk.CTkButton(
            back_frame,
            text="↩️ Back",
            command=self.master.go_back,
            width=100,
            fg_color="transparent",
            text_color=("gray10", "gray90"),
            hover_color=("gray70", "gray30")
        )
        back_btn.pack(side="left")

        # Title
        ctk.CTkLabel(
            main_container,
            text="File Access Monitor",
            font=("Helvetica", 24, "bold")
        ).pack(pady=(0, 20))

        # Add Path Frame
        path_frame = ctk.CTkFrame(main_container)
        path_frame.pack(fill="x", pady=(0, 10))

        self.path_entry = ctk.CTkEntry(
            path_frame,
            placeholder_text="Enter directory path to monitor",
            width=400
        )
        self.path_entry.pack(side="left", padx=5, pady=5, expand=True)

        add_btn = ctk.CTkButton(
            path_frame,
            text="Add Path",
            command=self.add_monitored_path
        )
        add_btn.pack(side="right", padx=5, pady=5)

        # Monitored Paths Frame with Stop Button
        paths_frame = ctk.CTkFrame(main_container)
        paths_frame.pack(fill="x", pady=(0, 10))

        paths_header = ctk.CTkFrame(paths_frame, fg_color="transparent")
        paths_header.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            paths_header,
            text="Monitored Directories:",
            font=("Helvetica", 16, "bold")
        ).pack(side="left")

        self.stop_btn = ctk.CTkButton(
            paths_header,
            text="Stop Monitoring",
            command=self.stop_monitoring,
            width=120,
            fg_color="red",
            hover_color="darkred"
        )
        self.stop_btn.pack(side="right")

        self.paths_list = ctk.CTkTextbox(paths_frame, height=100)
        self.paths_list.pack(fill="x", padx=10, pady=5)

        # Log Frame
        log_frame = ctk.CTkFrame(main_container)
        log_frame.pack(fill="both", expand=True)

        ctk.CTkLabel(
            log_frame,
            text="Activity Log:",
            font=("Helvetica", 16, "bold")
        ).pack(anchor="w", padx=10, pady=5)

        self.log_text = ctk.CTkTextbox(log_frame)
        self.log_text.pack(fill="both", expand=True, padx=10, pady=5)

    def stop_monitoring(self):
        """Stop monitoring all paths"""
        try:
            # Stop all observers
            for observer in self.observers:
                observer.stop()
            for observer in self.observers:
                observer.join()
            
            # Clear the lists
            self.observers.clear()
            self.monitored_paths.clear()
            
            # Clear the paths display
            self.paths_list.delete("1.0", "end")
            
            self.log_event("✅ Stopped monitoring all paths")
        except Exception as e:
            self.log_event(f"❌ Error stopping monitoring: {str(e)}")

    def add_monitored_path(self):
        path = self.path_entry.get().strip()
        
        # Handle drive paths (e.g., "C:", "C:\", "D:\")
        if len(path) == 1 and path.isalpha():
            path = f"{path}:\\"
        elif len(path) == 2 and path.endswith(":"):
            path = f"{path}\\"
        
        # Check if path exists and is accessible
        try:
            # Try to list directory contents to verify access
            os.listdir(path)
            if path not in self.monitored_paths:
                self.monitored_paths.append(path)
                self.paths_list.insert("end", f"📁 {path}\n")
                self.start_monitoring_path(path)
                self.log_event(f"✅ Now monitoring: {path}")
            self.path_entry.delete(0, 'end')
        except (PermissionError, OSError) as e:
            self.log_event(f"❌ Cannot access path: {path} - {str(e)}")
        except Exception as e:
            self.log_event(f"❌ Invalid path: {path} - {str(e)}")

    def start_monitoring_path(self, path):
        try:
            event_handler = FileMonitorHandler(self)
            observer = Observer()
            observer.schedule(event_handler, path, recursive=True)
            observer.start()
            self.observers.append(observer)
        except Exception as e:
            self.log_event(f"❌ Error starting monitoring: {str(e)}")

    def log_event(self, message):
        """Log an event with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")

    def ask_permission(self, message):
        """Show a modal dialog that blocks until user responds"""
        # Create a modal dialog
        dialog = ctk.CTkToplevel(self)
        dialog.title("Permission Required")
        dialog.geometry("400x150")
        dialog.transient(self.winfo_toplevel())  # Set main window as parent
        
        # Make dialog modal and force focus
        dialog.grab_set()  # Make dialog modal
        dialog.focus_force()  # Force focus on dialog
        
        # Prevent closing the dialog with the 'X' button
        dialog.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Center the dialog on the main window
        self.update_idletasks()
        main_window = self.winfo_toplevel()
        x = main_window.winfo_x() + (main_window.winfo_width() // 2) - (400 // 2)
        y = main_window.winfo_y() + (main_window.winfo_height() // 2) - (150 // 2)
        dialog.geometry(f'+{x}+{y}')
        
        # Keep dialog on top and make it modal
        dialog.attributes('-topmost', True)
        dialog.focus_set()
        
        # Add message
        msg_label = ctk.CTkLabel(
            dialog,
            text=message,
            wraplength=350
        )
        msg_label.pack(pady=20, padx=20)
        
        # Variable to store result
        result = [False]
        
        def on_yes():
            result[0] = True
            dialog.grab_release()
            dialog.destroy()
            
        def on_no():
            result[0] = False
            dialog.grab_release()
            dialog.destroy()
        
        # Add buttons
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)
        
        yes_btn = ctk.CTkButton(
            button_frame,
            text="Yes",
            command=on_yes,
            width=100
        )
        yes_btn.pack(side="left", padx=20, expand=True)
        
        no_btn = ctk.CTkButton(
            button_frame,
            text="No",
            command=on_no,
            width=100
        )
        no_btn.pack(side="right", padx=20, expand=True)
        
        # Focus on "No" button by default for safety
        no_btn.focus_set()
        
        # Bind Enter and Escape keys
        dialog.bind('<Return>', lambda e: on_no())
        dialog.bind('<Escape>', lambda e: on_no())
        
        # Wait for the dialog to be closed
        dialog.wait_window()
        return result[0]

    def on_close(self):
        """Stop all observers when closing"""
        self.stop_monitoring() 