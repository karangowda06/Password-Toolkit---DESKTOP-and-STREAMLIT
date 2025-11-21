import customtkinter as ctk
import string
import random

# =========================
# PASSWORD LOGIC
# =========================

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "letmein", "admin", "iloveyou", "welcome", "12345678"
}

def has_sequential_or_repeated_chars(pw: str) -> bool:
    if len(pw) < 3:
        return False
    # repeated like "aaa"
    for i in range(len(pw) - 2):
        if pw[i] == pw[i+1] == pw[i+2]:
            return True
    # simple ascending sequences like "abc", "123"
    for i in range(len(pw) - 2):
        a, b, c = pw[i], pw[i+1], pw[i+2]
        if a.isalnum() and b.isalnum() and c.isalnum():
            if ord(b) == ord(a) + 1 and ord(c) == ord(b) + 1:
                return True
    return False

def evaluate_password_strength(password: str) -> dict:
    score = 0
    suggestions = []
    length = len(password)

    if length == 0:
        return {
            "score": 0,
            "label": "No Password",
            "suggestions": ["Start typing to see the strength."],
            "has_lower": False,
            "has_upper": False,
            "has_digit": False,
            "has_symbol": False,
            "length": 0,
        }

    # length
    if length < 6:
        score += 5
        suggestions.append("Use at least 8 characters.")
    elif length < 8:
        score += 15
        suggestions.append("Longer passwords are stronger. Aim for 12+ characters.")
    elif length < 12:
        score += 30
    elif length < 16:
        score += 40
    else:
        score += 50

    # variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    for cond in (has_lower, has_upper, has_digit, has_symbol):
        if cond:
            score += 10

    if sum([has_lower, has_upper, has_digit, has_symbol]) <= 2:
        suggestions.append("Use a mix of lowercase, uppercase, numbers, and symbols.")

    # common
    if password.lower() in COMMON_PASSWORDS:
        score -= 25
        suggestions.append("Avoid very common passwords (like 'password', '123456').")

    # sequences / repeats
    if has_sequential_or_repeated_chars(password):
        score -= 10
        suggestions.append("Avoid obvious sequences or repeated characters (e.g. '1111', 'abcd').")

    score = max(0, min(score, 100))

    if score < 30:
        label = "Very Weak"
    elif score < 50:
        label = "Weak"
    elif score < 70:
        label = "Medium"
    elif score < 85:
        label = "Strong"
    else:
        label = "Very Strong"

    if not suggestions and score < 100:
        suggestions.append("This is a good password. Just make sure you don't reuse it on other sites.")

    return {
        "score": score,
        "label": label,
        "suggestions": suggestions,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "length": length,
    }

def generate_password(length: int, use_upper=True, use_digits=True, use_symbols=True) -> str:
    if length < 4:
        length = 4

    chars = string.ascii_lowercase
    mandatory = [random.choice(string.ascii_lowercase)]

    if use_upper:
        chars += string.ascii_uppercase
        mandatory.append(random.choice(string.ascii_uppercase))
    if use_digits:
        chars += string.digits
        mandatory.append(random.choice(string.digits))
    if use_symbols:
        chars += string.punctuation
        mandatory.append(random.choice(string.punctuation))

    remaining_len = max(length - len(mandatory), 0)
    pw_chars = mandatory + [random.choice(chars) for _ in range(remaining_len)]
    random.shuffle(pw_chars)
    return "".join(pw_chars)

def check_policy(password: str, min_length: int,
                 require_upper: bool, require_digits: bool, require_symbols: bool) -> dict:
    reasons = []
    if len(password) < min_length:
        reasons.append(f"Must be at least {min_length} characters long.")
    if require_upper and not any(c.isupper() for c in password):
        reasons.append("Must contain at least one uppercase letter.")
    if require_digits and not any(c.isdigit() for c in password):
        reasons.append("Must contain at least one digit.")
    if require_symbols and not any(c in string.punctuation for c in password):
        reasons.append("Must contain at least one symbol (e.g., !, @, #).")
    return {"compliant": len(reasons) == 0, "fail_reasons": reasons}

# =========================
# CUSTOMTKINTER APP
# =========================

ctk.set_appearance_mode("dark")          # "dark" / "light" / "system"
ctk.set_default_color_theme("blue")     # "blue", "green", "dark-blue"

class PasswordToolkitApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Password Toolkit - CustomTkinter")
        self.geometry("900x560")
        self.resizable(False, False)

        # Root layout
        main_frame = ctk.CTkFrame(self, corner_radius=15)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)

        header = ctk.CTkFrame(main_frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(15, 5))

        title = ctk.CTkLabel(
            header,
            text="🔐 Password Toolkit",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            header,
            text="Strength checker, password generator, and policy tester.",
            font=ctk.CTkFont(size=13),
        )
        subtitle.pack(anchor="w")

        # Tabs
        tabs = ctk.CTkTabview(main_frame, corner_radius=12)
        tabs.pack(expand=True, fill="both", padx=20, pady=20)

        self.tab_checker = tabs.add("🧪 Strength Checker")
        self.tab_generator = tabs.add("🎲 Generator")
        self.tab_policy = tabs.add("📏 Policy Tester")

        self._build_checker_tab()
        self._build_generator_tab()
        self._build_policy_tab()

    # ------------- TAB 1: Strength Checker -------------
    def _build_checker_tab(self):
        frame = self.tab_checker

        top = ctk.CTkFrame(frame)
        top.pack(fill="x", padx=10, pady=10)

        label = ctk.CTkLabel(
            top,
            text="Type a password below (live strength view):",
            font=ctk.CTkFont(size=15),
        )
        label.pack(anchor="w", pady=(0, 8))

        entry_row = ctk.CTkFrame(frame, fg_color="transparent")
        entry_row.pack(fill="x", padx=10)

        self.check_pw_var = ctk.StringVar()
        self.check_entry = ctk.CTkEntry(
            entry_row,
            textvariable=self.check_pw_var,
            show="*",
            width=500,
            font=ctk.CTkFont(size=14),
        )
        self.check_entry.pack(side="left", fill="x", expand=True, pady=5)
        self.check_entry.bind("<KeyRelease>", self._on_checker_change)

        self.check_show_var = ctk.BooleanVar(value=False)
        show_switch = ctk.CTkSwitch(
            entry_row,
            text="Show",
            variable=self.check_show_var,
            command=self._toggle_check_show,
        )
        show_switch.pack(side="left", padx=10)

        # Strength label
        self.check_strength_label = ctk.CTkLabel(
            frame,
            text="Start typing to evaluate the password.",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.check_strength_label.pack(anchor="w", padx=10, pady=(8, 4))

        # Progress bar
        self.check_progress = ctk.CTkProgressBar(frame, height=16)
        self.check_progress.pack(fill="x", padx=10)
        self.check_progress.set(0)

        # Live requirements
        req_frame = ctk.CTkFrame(frame)
        req_frame.pack(fill="x", padx=10, pady=15)

        self.req_len_label = ctk.CTkLabel(req_frame, text="✖ Length ≥ 8")
        self.req_lower_label = ctk.CTkLabel(req_frame, text="✖ Lowercase")
        self.req_upper_label = ctk.CTkLabel(req_frame, text="✖ Uppercase")
        self.req_digit_label = ctk.CTkLabel(req_frame, text="✖ Digit")
        self.req_symbol_label = ctk.CTkLabel(req_frame, text="✖ Symbol")

        self.req_len_label.grid(row=0, column=0, padx=5, pady=3)
        self.req_lower_label.grid(row=0, column=1, padx=5, pady=3)
        self.req_upper_label.grid(row=0, column=2, padx=5, pady=3)
        self.req_digit_label.grid(row=0, column=3, padx=5, pady=3)
        self.req_symbol_label.grid(row=0, column=4, padx=5, pady=3)

        for i in range(5):
            req_frame.grid_columnconfigure(i, weight=1)

        # Suggestions box
        sugg_label = ctk.CTkLabel(
            frame,
            text="Tips & Suggestions:",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        sugg_label.pack(anchor="w", padx=10, pady=(5, 2))

        self.sugg_box = ctk.CTkTextbox(frame, height=160)
        self.sugg_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.sugg_box.insert("1.0", "Start typing a password to see suggestions here.")
        self.sugg_box.configure(state="disabled")

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(pady=5)

        refresh_btn = ctk.CTkButton(
            btn_row,
            text="Re-check Now",
            command=self._update_checker_view,
            corner_radius=18,
            width=140,
        )
        refresh_btn.pack()

    def _toggle_check_show(self):
        self.check_entry.configure(
            show="" if self.check_show_var.get() else "*"
        )

    def _on_checker_change(self, event=None):
        self._update_checker_view()

    def _set_req_label(self, widget: ctk.CTkLabel, ok: bool, text: str):
        widget.configure(text=text)
        if ok:
            widget.configure(text_color="#7CFC00")  # light green
        else:
            widget.configure(text_color="#FF6347")  # tomato

    def _update_checker_view(self):
        pw = self.check_pw_var.get()
        result = evaluate_password_strength(pw)

        score = result["score"]
        label = result["label"]
        suggestions = result["suggestions"]

        self.check_progress.set(score / 100)

        emoji = "😴"
        if label == "Very Weak":
            emoji = "🟥"
        elif label == "Weak":
            emoji = "🟧"
        elif label == "Medium":
            emoji = "🟨"
        elif label == "Strong":
            emoji = "🟩"
        elif label == "Very Strong":
            emoji = "💪"

        self.check_strength_label.configure(
            text=f"{emoji} Score: {score} / 100  ({label})"
        )

        self._set_req_label(
            self.req_len_label,
            result["length"] >= 8,
            f"{'✔' if result['length'] >= 8 else '✖'} Length ≥ 8",
        )
        self._set_req_label(
            self.req_lower_label,
            result["has_lower"],
            f"{'✔' if result['has_lower'] else '✖'} Lowercase",
        )
        self._set_req_label(
            self.req_upper_label,
            result["has_upper"],
            f"{'✔' if result['has_upper'] else '✖'} Uppercase",
        )
        self._set_req_label(
            self.req_digit_label,
            result["has_digit"],
            f"{'✔' if result['has_digit'] else '✖'} Digit",
        )
        self._set_req_label(
            self.req_symbol_label,
            result["has_symbol"],
            f"{'✔' if result['has_symbol'] else '✖'} Symbol",
        )

        self.sugg_box.configure(state="normal")
        self.sugg_box.delete("1.0", "end")
        for s in suggestions:
            self.sugg_box.insert("end", f"• {s}\n")
        self.sugg_box.configure(state="disabled")

    # ------------- TAB 2: Generator -------------
    def _build_generator_tab(self):
        frame = self.tab_generator

        top = ctk.CTkFrame(frame)
        top.pack(fill="x", padx=10, pady=10)

        lbl = ctk.CTkLabel(
            top,
            text="Generate a strong password:",
            font=ctk.CTkFont(size=15),
        )
        lbl.pack(anchor="w", pady=(0, 8))

        config = ctk.CTkFrame(frame)
        config.pack(fill="x", padx=10, pady=5)

        length_label = ctk.CTkLabel(config, text="Length:")
        length_label.grid(row=0, column=0, sticky="w", pady=5)

        self.gen_length_var = ctk.IntVar(value=12)

        self.gen_length_slider = ctk.CTkSlider(
            config,
            from_=6,
            to=32,
            number_of_steps=26,
            variable=self.gen_length_var,
            command=lambda v: self._update_gen_length_label(),
        )
        self.gen_length_slider.grid(row=0, column=1, sticky="we", padx=8, pady=5)
        config.grid_columnconfigure(1, weight=1)

        self.gen_length_text = ctk.CTkLabel(config, text="12")
        self.gen_length_text.grid(row=0, column=2, sticky="w", padx=5)

        # Toggles
        toggle_row = ctk.CTkFrame(frame)
        toggle_row.pack(fill="x", padx=10, pady=8)

        self.gen_upper_switch = ctk.CTkSwitch(
            toggle_row, text="Include uppercase A–Z", switch_width=40, switch_height=20
        )
        self.gen_upper_switch.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.gen_upper_switch.select()

        self.gen_digits_switch = ctk.CTkSwitch(
            toggle_row, text="Include digits 0–9", switch_width=40, switch_height=20
        )
        self.gen_digits_switch.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.gen_digits_switch.select()

        self.gen_symbols_switch = ctk.CTkSwitch(
            toggle_row,
            text="Include symbols (!,@,#,...)",
            switch_width=40,
            switch_height=20,
        )
        self.gen_symbols_switch.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.gen_symbols_switch.select()

        for i in range(3):
            toggle_row.grid_columnconfigure(i, weight=1)

        # Generate button
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(pady=5)

        gen_btn = ctk.CTkButton(
            btn_row,
            text="Generate Password",
            corner_radius=18,
            width=180,
            command=self._on_generate_clicked,
        )
        gen_btn.pack()

        # Result
        result_frame = ctk.CTkFrame(frame)
        result_frame.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(result_frame, text="Generated password:").pack(anchor="w")

        self.gen_pw_var = ctk.StringVar()
        self.gen_entry = ctk.CTkEntry(
            result_frame,
            textvariable=self.gen_pw_var,
            font=ctk.CTkFont(size=14),
        )
        self.gen_entry.pack(fill="x", expand=True, pady=5)

        copy_btn = ctk.CTkButton(
            result_frame,
            text="Copy to clipboard",
            width=150,
            corner_radius=16,
            command=self._copy_generated,
        )
        copy_btn.pack(anchor="e", pady=(0, 5))

        # Strength
        self.gen_strength_label = ctk.CTkLabel(
            frame,
            text="Strength: N/A",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.gen_strength_label.pack(anchor="w", padx=10, pady=(8, 4))

        self.gen_progress = ctk.CTkProgressBar(frame, height=16)
        self.gen_progress.pack(fill="x", padx=10, pady=(0, 10))
        self.gen_progress.set(0)

    def _update_gen_length_label(self):
        self.gen_length_text.configure(text=str(int(self.gen_length_var.get())))

    def _on_generate_clicked(self):
        length = int(self.gen_length_var.get())
        pw = generate_password(
            length,
            use_upper=self.gen_upper_switch.get(),
            use_digits=self.gen_digits_switch.get(),
            use_symbols=self.gen_symbols_switch.get(),
        )
        self.gen_pw_var.set(pw)

        result = evaluate_password_strength(pw)
        score = result["score"]
        label = result["label"]
        self.gen_progress.set(score / 100)

        emoji = "🟥"
        if label == "Weak":
            emoji = "🟧"
        elif label == "Medium":
            emoji = "🟨"
        elif label == "Strong":
            emoji = "🟩"
        elif label == "Very Strong":
            emoji = "💪"

        self.gen_strength_label.configure(
            text=f"{emoji} Strength: {score}/100 – {label}"
        )

    def _copy_generated(self):
        pw = self.gen_pw_var.get()
        if not pw:
            return
        self.clipboard_clear()
        self.clipboard_append(pw)

    # ------------- TAB 3: Policy Tester -------------
    def _build_policy_tab(self):
        frame = self.tab_policy

        top = ctk.CTkFrame(frame)
        top.pack(fill="x", padx=10, pady=10)

        lbl = ctk.CTkLabel(
            top,
            text="Set a password policy and test any password:",
            font=ctk.CTkFont(size=15),
        )
        lbl.pack(anchor="w", pady=(0, 8))

        policy_frame = ctk.CTkFrame(frame)
        policy_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(policy_frame, text="Minimum length:").grid(
            row=0, column=0, sticky="w", pady=5
        )

        self.policy_len_var = ctk.IntVar(value=10)
        self.policy_len_slider = ctk.CTkSlider(
            policy_frame,
            from_=4,
            to=32,
            number_of_steps=28,
            variable=self.policy_len_var,
            command=lambda v: self._update_policy_len_label(),
        )
        self.policy_len_slider.grid(row=0, column=1, padx=8, pady=5, sticky="we")
        policy_frame.grid_columnconfigure(1, weight=1)

        self.policy_len_text = ctk.CTkLabel(policy_frame, text="10")
        self.policy_len_text.grid(row=0, column=2, padx=5, sticky="w")

        toggle_row = ctk.CTkFrame(policy_frame, fg_color="transparent")
        toggle_row.grid(row=1, column=0, columnspan=3, pady=(8, 4), sticky="w")

        self.policy_upper_switch = ctk.CTkSwitch(
            toggle_row, text="Require uppercase", switch_width=40, switch_height=20
        )
        self.policy_upper_switch.grid(row=0, column=0, padx=5, pady=4, sticky="w")
        self.policy_upper_switch.select()

        self.policy_digit_switch = ctk.CTkSwitch(
            toggle_row, text="Require digits", switch_width=40, switch_height=20
        )
        self.policy_digit_switch.grid(row=0, column=1, padx=5, pady=4, sticky="w")
        self.policy_digit_switch.select()

        self.policy_symbol_switch = ctk.CTkSwitch(
            toggle_row, text="Require symbols", switch_width=40, switch_height=20
        )
        self.policy_symbol_switch.grid(row=0, column=2, padx=5, pady=4, sticky="w")
        self.policy_symbol_switch.select()

        for i in range(3):
            toggle_row.grid_columnconfigure(i, weight=1)

        # Password input
        pw_frame = ctk.CTkFrame(frame)
        pw_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(pw_frame, text="Password to test:").pack(anchor="w")
        self.policy_pw_var = ctk.StringVar()
        self.policy_entry = ctk.CTkEntry(
            pw_frame,
            textvariable=self.policy_pw_var,
            show="*",
            font=ctk.CTkFont(size=14),
        )
        self.policy_entry.pack(fill="x", expand=True, pady=5)
        self.policy_entry.bind("<KeyRelease>", self._on_policy_live)

        self.policy_show_var = ctk.BooleanVar(value=False)
        show_switch = ctk.CTkSwitch(
            pw_frame,
            text="Show password",
            variable=self.policy_show_var,
            command=self._toggle_policy_show,
        )
        show_switch.pack(anchor="w", pady=(0, 5))

        # Result
        result_row = ctk.CTkFrame(frame, fg_color="transparent")
        result_row.pack(fill="x", padx=10, pady=(0, 5))

        self.policy_result_label = ctk.CTkLabel(
            result_row,
            text="Waiting for input...",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        self.policy_result_label.pack(side="left")

        # Details textbox
        self.policy_details_box = ctk.CTkTextbox(frame, height=160)
        self.policy_details_box.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        self.policy_details_box.insert("1.0", "Start typing a password to test it.")
        self.policy_details_box.configure(state="disabled")

        # Manual test button
        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(pady=(0, 8))

        test_btn = ctk.CTkButton(
            btn_row,
            text="Test Policy Compliance",
            corner_radius=18,
            width=200,
            command=self._run_policy_check,
        )
        test_btn.pack()

    def _update_policy_len_label(self):
        self.policy_len_text.configure(text=str(int(self.policy_len_var.get())))

    def _toggle_policy_show(self):
        self.policy_entry.configure(
            show="" if self.policy_show_var.get() else "*"
        )

    def _on_policy_live(self, event=None):
        self._run_policy_check(live=True)

    def _run_policy_check(self, live: bool = False):
        pw = self.policy_pw_var.get()
        if not pw and live:
            self.policy_result_label.configure(text="Waiting for input...")
            self.policy_details_box.configure(state="normal")
            self.policy_details_box.delete("1.0", "end")
            self.policy_details_box.insert("1.0", "Start typing a password to test it.")
            self.policy_details_box.configure(state="disabled")
            return

        min_len = int(self.policy_len_var.get())
        res = check_policy(
            pw,
            min_length=min_len,
            require_upper=self.policy_upper_switch.get(),
            require_digits=self.policy_digit_switch.get(),
            require_symbols=self.policy_symbol_switch.get(),
        )

        self.policy_details_box.configure(state="normal")
        self.policy_details_box.delete("1.0", "end")

        if res["compliant"]:
            self.policy_result_label.configure(text="✅ Password MEETS the policy.")
            self.policy_details_box.insert(
                "1.0", "The password satisfies all policy requirements."
            )
        else:
            self.policy_result_label.configure(
                text="❌ Password does NOT meet the policy."
            )
            for r in res["fail_reasons"]:
                self.policy_details_box.insert("end", f"• {r}\n")

        self.policy_details_box.configure(state="disabled")


if __name__ == "__main__":
    app = PasswordToolkitApp()
    app.mainloop()
