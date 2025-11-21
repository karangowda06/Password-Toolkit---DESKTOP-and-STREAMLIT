import streamlit as st
import string
import random

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "letmein", "admin", "iloveyou", "welcome", "12345678"
}

def has_sequential_or_repeated_chars(pw: str) -> bool:
    if len(pw) < 3:
        return False
    for i in range(len(pw) - 2):
        if pw[i] == pw[i+1] == pw[i+2]:
            return True
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

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    for cond in (has_lower, has_upper, has_digit, has_symbol):
        if cond:
            score += 10

    if sum([has_lower, has_upper, has_digit, has_symbol]) <= 2:
        suggestions.append("Use a mix of lowercase, uppercase, numbers, and symbols.")

    if password.lower() in COMMON_PASSWORDS:
        score -= 25
        suggestions.append("Avoid very common passwords (like 'password', '123456').")

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
# STREAMLIT APP
# =========================

st.set_page_config(page_title="Password Toolkit", page_icon="🔐", layout="centered")

st.title("🔐 Password Toolkit")
st.caption("Password strength checker, generator, and policy tester – web interface.")

tab1, tab2, tab3 = st.tabs(["🧪 Strength Checker", "🎲 Generator", "📏 Policy Tester"])

# ---------- Tab 1 ----------
with tab1:
    st.subheader("Password Strength Checker")

    col1, col2 = st.columns([3, 1])
    with col1:
        pw = st.text_input("Enter password", type="password")
    with col2:
        show_pw = st.checkbox("Show password")
    if show_pw and pw:
        st.info(f"Password: `{pw}`")

    result = evaluate_password_strength(pw)
    score = result["score"]
    label = result["label"]

    st.write(f"**Score:** {score} / 100  –  **{label}**")
    st.progress(score / 100)

    cols = st.columns(5)
    cols[0].metric("Length ≥ 8", "✔" if result["length"] >= 8 else "✖")
    cols[1].metric("Lowercase", "✔" if result["has_lower"] else "✖")
    cols[2].metric("Uppercase", "✔" if result["has_upper"] else "✖")
    cols[3].metric("Digit", "✔" if result["has_digit"] else "✖")
    cols[4].metric("Symbol", "✔" if result["has_symbol"] else "✖")

    st.markdown("**Suggestions:**")
    for s in result["suggestions"]:
        st.write(f"- {s}")

# ---------- Tab 2 ----------
with tab2:
    st.subheader("Password Generator")

    length = st.slider("Length", min_value=6, max_value=32, value=12)
    use_upper = st.toggle("Include uppercase A–Z", value=True)
    use_digits = st.toggle("Include digits 0–9", value=True)
    use_symbols = st.toggle("Include symbols (!,@,#,...)", value=True)

    if st.button("Generate Password"):
        pw_gen = generate_password(length, use_upper, use_digits, use_symbols)
        st.session_state["generated_pw"] = pw_gen

    pw_generated = st.session_state.get("generated_pw", "")
    if pw_generated:
        st.code(pw_generated, language="text")
        res_gen = evaluate_password_strength(pw_generated)
        score_g = res_gen["score"]
        label_g = res_gen["label"]
        st.write(f"**Strength:** {score_g}/100 – {label_g}")
        st.progress(score_g / 100)

# ---------- Tab 3 ----------
with tab3:
    st.subheader("Policy Tester")

    colA, colB = st.columns(2)
    with colA:
        min_len = st.number_input("Minimum length", min_value=4, max_value=64, value=10, step=1)
    with colB:
        st.write("")
        st.write("")

    require_upper = st.toggle("Require uppercase letters", value=True)
    require_digits = st.toggle("Require digits", value=True)
    require_symbols = st.toggle("Require symbols", value=True)

    pw_policy = st.text_input("Password to test (policy)", type="password")

    if pw_policy:
        res = check_policy(
            pw_policy,
            min_length=int(min_len),
            require_upper=require_upper,
            require_digits=require_digits,
            require_symbols=require_symbols
        )
        if res["compliant"]:
            st.success("✅ Password MEETS the policy.")
        else:
            st.error("❌ Password does NOT meet the policy.")
            for r in res["fail_reasons"]:
                st.write(f"- {r}")
    else:
        st.info("Enter a password above to test against the policy.")
