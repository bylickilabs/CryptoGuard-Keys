import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import webbrowser

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives import serialization
 
APP_NAME = "CryptoGuard Keys"
APP_TITLE = "Advanced Key Management & Generation Console"
APP_COMPANY = "©Thorsten Bylicki | ©BYLICKILABS"
APP_VERSION = "1.0.0"
GITHUB_URL = "https://github.com/bylickilabs/CryptoGuard-Keys"

class LanguageManager:
    def __init__(self):
        self.current = "de"
        self.strings = {
            "de": {
                "window_title": f"{APP_NAME} | Kryptografische Schlüsselverwaltung",
                "menu_language": "Sprache",
                "menu_language_de": "Deutsch",
                "menu_language_en": "Englisch",
                "menu_help": "Hilfe",
                "menu_help_github": "GitHub-Projektseite",
                "menu_help_info": "Info über Anwendung",
                "menu_exit": "Beenden",
                "label_language": "Sprache:",
                "label_algorithm": "Algorithmus / Profil",
                "label_keysize": "Schlüssellänge / Profil",
                "label_public": "Öffentlicher Schlüssel (PEM)",
                "label_private": "Privater Schlüssel (PEM)",
                "btn_generate": "Schlüsselpaar generieren",
                "btn_clear": "Felder leeren",
                "btn_copy_public": "Öffentlichen Schlüssel kopieren",
                "btn_copy_private": "Privaten Schlüssel kopieren",
                "btn_github": "GitHub öffnen",
                "btn_info": "Info",
                "status_ready": "Bereit.",
                "status_generating": "Schlüsselpaar wird generiert…",
                "status_done": "Schlüsselpaar erfolgreich generiert.",
                "status_cleared": "Ausgaben gelöscht.",
                "status_copied_public": "Öffentlicher Schlüssel in Zwischenablage kopiert.",
                "status_copied_private": "Privater Schlüssel in Zwischenablage kopiert.",
                "error_title": "Fehler",
                "error_generation": "Bei der Schlüsselerzeugung ist ein Fehler aufgetreten.",
                "error_clipboard": "Konnte Text nicht in die Zwischenablage kopieren.",
                "info_title": "Anwendungsinformationen",
                "info_body": (
                    f"{APP_TITLE}\n\n"
                    f"Name: {APP_NAME}\n"
                    f"Version: {APP_VERSION}\n"
                    f"Unternehmen: {APP_COMPANY}\n\n"
                    "CryptoGuard Keys ist eine professionelle Desktop-Konsole für die "
                    "Erzeugung und Verwaltung kryptografischer Schlüsselpaare. "
                    "Unterstützt werden aktuell RSA (2048/3072/4096 Bit), "
                    "Elliptic-Curve-Profile (secp256r1, secp384r1) sowie Ed25519 "
                    "und X25519.\n\n"
                    "Die Anwendung nutzt die etablierte Python-Bibliothek "
                    "'cryptography' und erzeugt Schlüssel in standardkonformen "
                    "PEM-Formaten, die direkt in andere Werkzeuge, Dienste oder "
                    "eigene Anwendungen integriert werden können.\n\n"
                    "Die Benutzeroberfläche ist vollständig zweisprachig "
                    "(Deutsch / Englisch) ausgelegt und kann bei Bedarf erweitert "
                    "und in bestehende BYLICKILABS-Toolchains integriert werden."
                ),
                "info_github_open": "Die GitHub-Projektseite wird im Standardbrowser geöffnet.",
                "confirm_exit_title": "Anwendung beenden",
                "confirm_exit_body": "Möchten Sie CryptoGuard Keys wirklich beenden?",
            },
            "en": {
                "window_title": f"{APP_NAME} | Cryptographic Key Management",
                "menu_language": "Language",
                "menu_language_de": "German",
                "menu_language_en": "English",
                "menu_help": "Help",
                "menu_help_github": "GitHub project page",
                "menu_help_info": "About this application",
                "menu_exit": "Exit",
                "label_language": "Language:",
                "label_algorithm": "Algorithm / Profile",
                "label_keysize": "Key size / profile",
                "label_public": "Public key (PEM)",
                "label_private": "Private key (PEM)",
                "btn_generate": "Generate key pair",
                "btn_clear": "Clear fields",
                "btn_copy_public": "Copy public key",
                "btn_copy_private": "Copy private key",
                "btn_github": "Open GitHub",
                "btn_info": "Info",
                "status_ready": "Ready.",
                "status_generating": "Generating key pair…",
                "status_done": "Key pair generated successfully.",
                "status_cleared": "Output cleared.",
                "status_copied_public": "Public key copied to clipboard.",
                "status_copied_private": "Private key copied to clipboard.",
                "error_title": "Error",
                "error_generation": "An error occurred while generating the key.",
                "error_clipboard": "Could not copy text to clipboard.",
                "info_title": "Application information",
                "info_body": (
                    f"{APP_TITLE}\n\n"
                    f"Name: {APP_NAME}\n"
                    f"Version: {APP_VERSION}\n"
                    f"Company: {APP_COMPANY}\n\n"
                    "CryptoGuard Keys is a professional desktop console for generating "
                    "and managing cryptographic key pairs. It currently supports RSA "
                    "(2048/3072/4096 bits), elliptic curve profiles (secp256r1, "
                    "secp384r1) as well as Ed25519 and X25519.\n\n"
                    "The application uses the well-established Python library "
                    "'cryptography' and produces keys in standards-compliant PEM "
                    "formats that can be integrated directly into other tools, "
                    "services or your own applications.\n\n"
                    "The user interface is fully bilingual (German / English) and "
                    "can be extended and integrated into existing BYLICKILABS "
                    "toolchains as needed."
                ),
                "info_github_open": "The GitHub project page will be opened in your default browser.",
                "confirm_exit_title": "Exit application",
                "confirm_exit_body": "Do you really want to close CryptoGuard Keys?",
            },
        }

    def set_language(self, lang_code: str):
        if lang_code in self.strings:
            self.current = lang_code

    def t(self, key: str) -> str:
        return self.strings.get(self.current, {}).get(key, key)


class CryptoGuardApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.lang = LanguageManager()

        self.geometry("950x650")
        self.minsize(900, 600)

        self._create_widgets()
        self._create_menus()
        self._apply_language()

        self.protocol("WM_DELETE_WINDOW", self.on_exit)

    def _create_menus(self):
        self.menubar = tk.Menu(self)
        self.config(menu=self.menubar)
        self._build_menus()

    def _build_menus(self):
        self.menubar.delete(0, tk.END)

        self.language_menu = tk.Menu(self.menubar, tearoff=0)
        self.help_menu = tk.Menu(self.menubar, tearoff=0)

        self.menubar.add_cascade(label=self.lang.t("menu_language"), menu=self.language_menu)
        self.menubar.add_cascade(label=self.lang.t("menu_help"), menu=self.help_menu)
        self.menubar.add_command(label=self.lang.t("menu_exit"), command=self.on_exit)

        self.language_menu.add_command(
            label=self.lang.t("menu_language_de"), command=lambda: self.change_language("de")
        )
        self.language_menu.add_command(
            label=self.lang.t("menu_language_en"), command=lambda: self.change_language("en")
        )
        self.help_menu.add_command(
            label=self.lang.t("menu_help_github"), command=self.open_github
        )
        self.help_menu.add_command(
            label=self.lang.t("menu_help_info"), command=self.show_info
        )

    def _create_widgets(self):
        main = ttk.Frame(self)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        top_bar = ttk.Frame(main)
        top_bar.pack(fill=tk.X)

        self.lbl_language = ttk.Label(top_bar, text="")
        self.lbl_language.pack(side=tk.LEFT)

        self.combo_language = ttk.Combobox(
            top_bar,
            state="readonly",
            values=["Deutsch", "English"],
            width=12,
        )
        self.combo_language.current(0)
        self.combo_language.bind("<<ComboboxSelected>>", self._on_combo_language_change)
        self.combo_language.pack(side=tk.LEFT, padx=(5, 20))

        self.btn_github = ttk.Button(top_bar, text="", command=self.open_github)
        self.btn_github.pack(side=tk.RIGHT, padx=(5, 0))

        self.btn_info = ttk.Button(top_bar, text="", command=self.show_info)
        self.btn_info.pack(side=tk.RIGHT, padx=(5, 5))

        self.algo_frame = ttk.LabelFrame(main, text="")
        self.algo_frame.pack(fill=tk.X, pady=(10, 5))

        self.combo_algorithm = ttk.Combobox(
            self.algo_frame,
            state="readonly",
            values=[
                "RSA-2048",
                "RSA-3072",
                "RSA-4096",
                "EC-secp256r1",
                "EC-secp384r1",
                "Ed25519",
                "X25519",
            ],
            width=20,
        )
        self.combo_algorithm.current(0)
        self.combo_algorithm.pack(side=tk.LEFT, padx=10, pady=5)

        self.lbl_keysize_label = ttk.Label(self.algo_frame, text="")
        self.lbl_keysize_label.pack(side=tk.LEFT, padx=(20, 5))

        self.lbl_profile_detail = ttk.Label(self.algo_frame, text="")
        self.lbl_profile_detail.pack(side=tk.LEFT, padx=(0, 10))

        self.combo_algorithm.bind("<<ComboboxSelected>>", self._on_algorithm_change)

        button_frame = ttk.Frame(main)
        button_frame.pack(fill=tk.X, pady=(5, 5))

        self.btn_generate = ttk.Button(
            button_frame,
            text="",
            command=self.generate_keypair,
        )
        self.btn_generate.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_clear = ttk.Button(
            button_frame,
            text="",
            command=self.clear_output,
        )
        self.btn_clear.pack(side=tk.LEFT, padx=(0, 5))

        self.btn_copy_public = ttk.Button(
            button_frame,
            text="",
            command=lambda: self.copy_to_clipboard(self.txt_public.get("1.0", tk.END), "public"),
        )
        self.btn_copy_public.pack(side=tk.RIGHT, padx=(5, 0))

        self.btn_copy_private = ttk.Button(
            button_frame,
            text="",
            command=lambda: self.copy_to_clipboard(self.txt_private.get("1.0", tk.END), "private"),
        )
        self.btn_copy_private.pack(side=tk.RIGHT, padx=(5, 5))

        text_frame = ttk.Panedwindow(main, orient=tk.HORIZONTAL)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 5))

        self.public_frame = ttk.LabelFrame(text_frame, text="")
        self.private_frame = ttk.LabelFrame(text_frame, text="")

        self.txt_public = scrolledtext.ScrolledText(self.public_frame, wrap=tk.NONE)
        self.txt_public.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.txt_private = scrolledtext.ScrolledText(self.private_frame, wrap=tk.NONE)
        self.txt_private.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        text_frame.add(self.public_frame, weight=1)
        text_frame.add(self.private_frame, weight=1)

        self.status_var = tk.StringVar(value="")
        status_bar = ttk.Label(main, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))


    def _apply_language(self):
        self.title(self.lang.t("window_title"))

        self._build_menus()

        self.lbl_language.config(text=self.lang.t("label_language"))
        self.btn_github.config(text=self.lang.t("btn_github"))
        self.btn_info.config(text=self.lang.t("btn_info"))
        self.btn_generate.config(text=self.lang.t("btn_generate"))
        self.btn_clear.config(text=self.lang.t("btn_clear"))
        self.btn_copy_public.config(text=self.lang.t("btn_copy_public"))
        self.btn_copy_private.config(text=self.lang.t("btn_copy_private"))

        self.algo_frame.config(text=self.lang.t("label_algorithm"))
        self.lbl_keysize_label.config(text=self.lang.t("label_keysize"))
        self.public_frame.config(text=self.lang.t("label_public"))
        self.private_frame.config(text=self.lang.t("label_private"))

        self.status_var.set(self.lang.t("status_ready"))
        self._update_profile_label()

    def _on_combo_language_change(self, event=None):
        selection = self.combo_language.get()
        if selection == "Deutsch":
            self.change_language("de")
        else:
            self.change_language("en")

    def change_language(self, lang_code: str):
        self.lang.set_language(lang_code)
        if lang_code == "de":
            self.combo_language.set("Deutsch")
        else:
            self.combo_language.set("English")
        self._apply_language()

    def _on_algorithm_change(self, event=None):
        self._update_profile_label()

    def _update_profile_label(self):
        algo = self.combo_algorithm.get()
        lang = self.lang.current
        if algo.startswith("RSA-"):
            bits = algo.split("-")[1]
            if lang == "de":
                txt = f"RSA {bits} Bit"
            else:
                txt = f"RSA {bits}-bit"
        elif algo == "EC-secp256r1":
            txt = "NIST P-256 / secp256r1"
        elif algo == "EC-secp384r1":
            txt = "NIST P-384 / secp384r1"
        elif algo == "Ed25519":
            txt = "Ed25519 signing key"
        elif algo == "X25519":
            txt = "X25519 key exchange key"
        else:
            txt = ""
        self.lbl_profile_detail.config(text=txt)

    def generate_keypair(self):
        algo = self.combo_algorithm.get()
        self.status_var.set(self.lang.t("status_generating"))
        self.update_idletasks()

        try:
            if algo.startswith("RSA-"):
                bits = int(algo.split("-")[1])
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=bits,
                )
            elif algo == "EC-secp256r1":
                private_key = ec.generate_private_key(ec.SECP256R1())
            elif algo == "EC-secp384r1":
                private_key = ec.generate_private_key(ec.SECP384R1())
            elif algo == "Ed25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
            elif algo == "X25519":
                private_key = x25519.X25519PrivateKey.generate()
            else:
                raise ValueError("Unsupported algorithm")

            public_key = private_key.public_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            self.txt_private.delete("1.0", tk.END)
            self.txt_public.delete("1.0", tk.END)

            self.txt_private.insert("1.0", private_pem)
            self.txt_public.insert("1.0", public_pem)

            self.status_var.set(self.lang.t("status_done"))
        except Exception as exc:
            print(f"Key generation error: {exc}")
            messagebox.showerror(self.lang.t("error_title"), self.lang.t("error_generation"))
            self.status_var.set(self.lang.t("status_ready"))

    def clear_output(self):
        self.txt_private.delete("1.0", tk.END)
        self.txt_public.delete("1.0", tk.END)
        self.status_var.set(self.lang.t("status_cleared"))

    def copy_to_clipboard(self, text: str, which: str):
        try:
            self.clipboard_clear()
            self.clipboard_append(text.strip())
            if which == "public":
                self.status_var.set(self.lang.t("status_copied_public"))
            else:
                self.status_var.set(self.lang.t("status_copied_private"))
        except Exception as exc:
            print(f"Clipboard error: {exc}")
            messagebox.showerror(self.lang.t("error_title"), self.lang.t("error_clipboard"))

    def open_github(self):
        webbrowser.open_new_tab(GITHUB_URL)
        messagebox.showinfo(APP_NAME, self.lang.t("info_github_open"))

    def show_info(self):
        messagebox.showinfo(self.lang.t("info_title"), self.lang.t("info_body"))

    def on_exit(self):
        if messagebox.askyesno(self.lang.t("confirm_exit_title"), self.lang.t("confirm_exit_body")):
            self.destroy()

if __name__ == "__main__":
    app = CryptoGuardApp()
    app.mainloop()
