# Password-Toolkit---DESKTOP-and-STREAMLIT


Here is a **clean, professional MAIN PROJECT README** that covers **both versions** of your Password Toolkit:

* **Streamlit Web App** (from your code) 
* **Windows EXE Desktop App** (from your packaged executable)

This README is designed to be placed at the **root of your GitHub repository** to represent the entire project.

---

# 🔐 **Password Toolkit – Complete Project**

A complete password utility suite offering both a **web-based app (Streamlit)** and a **desktop offline application (.exe)**.
The toolkit helps users **evaluate password strength**, **generate secure passwords**, and **validate them against customizable security policies**.

---

## 🌟 **Project Overview**

This project includes **two versions**:

### 1️⃣ **Streamlit Web Version**

* Runs in the browser
* Easy to use
* Live updates & dynamic UI
* Ideal for demos, learning, and quick usage

File: `password_toolkit_streamlit.py`
(Full code: )

---

### 2️⃣ **Windows Desktop EXE Version**

* Fully offline
* No installation or Python required
* Lightweight GUI
* Great for general users, security demos, or distribution

File: `password_toolkit_tk.exe`
*(Binary only — source code not included here)*

---

## 🚀 **Features (Both Versions)**

### 🔍 **Password Strength Checker**

* Scores password strength from **0–100**
* Labels: *Very Weak → Very Strong*
* Detects:

  * Short length
  * Missing character types
  * Repeated & sequential patterns
  * Common weak passwords
* Provides improvement suggestions

---

### 🎲 **Password Generator**

* Generates secure passwords
* Customizable length
* Toggle uppercase, digits, and symbols
* Ensures at least **one of each selected character type**
* Automatically evaluates the generated password

---

### 📏 **Custom Password Policy Tester**

* User-defined rules:

  * Minimum length
  * Require uppercase
  * Require numbers
  * Require symbols
* Shows:

  * Pass/Fail verdict
  * Detailed rule-based breakdown

---

## 🛠️ **Tech Stack**

### **Streamlit Version**

* Python
* Streamlit
* Built-in libraries: `random`, `string`

### **EXE Desktop Version**

* Python (Tkinter GUI before packaging)
* Packaged using **PyInstaller / auto-py-to-exe**
* Runs natively on Windows (no Python needed)

---

## 📦 **Installation & Usage**

### ▶️ **Option A — Streamlit Web App**

1. Install Streamlit:

   ```bash
   pip install streamlit
   ```

2. Run:

   ```bash
   streamlit run password_toolkit_streamlit.py
   ```

The app opens in your browser ([http://localhost:8501](http://localhost:8501)).

---

### ▶️ **Option B — Desktop EXE App**

1. Download `password_toolkit_tk.exe`
2. Double-click to run
3. No installation or dependencies needed

> ⚠️ On first launch, Windows may warn about "Unknown Publisher."
> Click **More Info → Run Anyway**.

---

## 📂 **Project Structure**

```
📁 Password-Toolkit/
│
├── password_toolkit_streamlit.py        # Streamlit web app
├── password_toolkit_tk.exe              # Desktop EXE build
│
├── README.md                            # (This file)
└── requirements.txt (optional)
```

---

## 🎯 **Use Cases**

* Teaching password security
* Helping users build strong passwords
* Demonstrating password policy rules
* Generating secure passwords for accounts
* Offline password testing (EXE version)

---

## 🔮 **Future Improvements (Optional Ideas)**

* Entropy calculation
* “No dictionary words” check
* Export generated passwords
* Password breach lookup (HIBP API)
* Dark mode UI

---

## 🤝 **Contributions**

Contributions, suggestions, and improvements are welcome!
Feel free to open an issue or submit a pull request.

---


