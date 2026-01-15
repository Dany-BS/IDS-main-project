import customtkinter as ctk
from tkinter import messagebox

class LoginWindow(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        
        # Valid credentials
        self.VALID_CREDENTIALS = {
            "admin": "admin123",
            "user1": "user123",
            "": ""
        }
        
        self.setup_ui()

    def setup_ui(self):
        # Create a gradient-like background frame
        bg_frame = ctk.CTkFrame(self, fg_color=("#E5EEF6", "#1A1A1A"))
        bg_frame.pack(fill="both", expand=True)

        # Create a centered frame for the login form
        frame = ctk.CTkFrame(
            bg_frame, 
            width=450,  # Increased width
            height=600,  # Increased height
            corner_radius=20,
            fg_color=("white", "gray17")
        )
        frame.place(relx=0.5, rely=0.5, anchor="center")
        frame.pack_propagate(False)

        # Main content container for vertical centering
        content_container = ctk.CTkFrame(frame, fg_color="transparent")
        content_container.place(relx=0.5, rely=0.5, anchor="center")

        # Logo/Brand section
        logo_frame = ctk.CTkFrame(content_container, fg_color="transparent")
        logo_frame.pack(pady=(0, 40))  # Increased bottom padding

        # IDS Logo/Title with decorative elements
        title_frame = ctk.CTkFrame(logo_frame, fg_color="transparent")
        title_frame.pack()

        # Decorative line left
        ctk.CTkFrame(title_frame, width=40, height=2, fg_color=("#3a7ebf", "#1f538d")).pack(side="left", padx=20, pady=30)

        # Title
        title_text = ctk.CTkFrame(title_frame, fg_color="transparent")
        title_text.pack(side="left")
        
        ctk.CTkLabel(
            title_text,
            text="IDS",
            font=("Helvetica", 52, "bold"),
            text_color=("#3a7ebf", "#1f538d")
        ).pack()

        ctk.CTkLabel(
            title_text,
            text="Intrusion Detection System",
            font=("Helvetica", 14),
            text_color="gray60"
        ).pack()

        # Decorative line right
        ctk.CTkFrame(title_frame, width=40, height=2, fg_color=("#3a7ebf", "#1f538d")).pack(side="left", padx=20, pady=30)

        # Login form container
        form_frame = ctk.CTkFrame(content_container, fg_color="transparent")
        form_frame.pack(pady=20)

        # Username input with icon
        username_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        username_frame.pack(fill="x", pady=(0, 20))
        
        ctk.CTkLabel(
            username_frame,
            text="👤",
            font=("Helvetica", 16),
            text_color="gray60"
        ).pack(side="left", padx=(0, 10))

        self.login_username = ctk.CTkEntry(
            username_frame,
            placeholder_text="Username",
            font=("Helvetica", 14),
            width=300,  # Fixed width
            height=45,  # Increased height
            corner_radius=10,
            border_width=1,
            fg_color=("white", "gray20")
        )
        self.login_username.pack()

        # Password input with icon
        password_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
        password_frame.pack(fill="x", pady=(0, 30))
        
        ctk.CTkLabel(
            password_frame,
            text="🔒",
            font=("Helvetica", 16),
            text_color="gray60"
        ).pack(side="left", padx=(0, 10))

        self.login_password = ctk.CTkEntry(
            password_frame,
            placeholder_text="Password",
            show="●",
            font=("Helvetica", 14),
            width=300,  # Fixed width
            height=45,  # Increased height
            corner_radius=10,
            border_width=1,
            fg_color=("white", "gray20")
        )
        self.login_password.pack()

        # Login button with hover effect
        login_button = ctk.CTkButton(
            form_frame,
            text="LOGIN",
            font=("Helvetica", 16, "bold"),
            width=300,  # Fixed width
            height=45,  # Increased height
            corner_radius=10,
            fg_color=("#3a7ebf", "#1f538d"),
            hover_color=("#325882", "#14375e"),
            command=self.handle_login
        )
        login_button.pack(pady=(0, 20))

        # Decorative bottom line
        ctk.CTkFrame(
            content_container,
            width=300,
            height=2,
            fg_color=("gray85", "gray30")
        ).pack(pady=(20, 25))

        # Footer text
        footer_frame = ctk.CTkFrame(content_container, fg_color="transparent")
        footer_frame.pack(pady=(0, 20))
        
        ctk.CTkLabel(
            footer_frame,
            text="Secure Access Control",
            font=("Helvetica", 12),
            text_color="gray60"
        ).pack()

        # Bind enter key to login
        self.login_username.bind("<Return>", lambda e: self.login_password.focus())
        self.login_password.bind("<Return>", lambda e: login_button.invoke())

    def handle_login(self):
        username = self.login_username.get()
        password = self.login_password.get()

        if username in self.VALID_CREDENTIALS and self.VALID_CREDENTIALS[username] == password:
            # Start monitoring before showing home window
            self.master.start_monitoring()
            self.master.show_home_window()
        else:
            messagebox.showerror("Error", "Invalid username or password!")

    def logout(self):
        """Handle user logout"""
        self.master.logout()  # Use the new logout method from MainApp 