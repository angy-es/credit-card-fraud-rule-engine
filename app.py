import streamlit as st
import requests
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Fraud Rule Engine", page_icon="shield", layout="wide")

API_BASE = "http://127.0.0.1:8010"

CUSTOM_CSS = """
<style>
.metric-card {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 10px;
    padding: 18px 20px;
    text-align: center;
}
.metric-card h2 {
    margin: 0;
    font-size: 28px;
    color: #E6EDF3;
}
.metric-card p {
    margin: 4px 0 0 0;
    color: #8B949E;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.decision-badge {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 999px;
    font-weight: 600;
    font-size: 15px;
}
.badge-approve { background-color: #1F3D2B; color: #3FB950; }
.badge-review { background-color: #3D341F; color: #D29922; }
.badge-decline { background-color: #3D1F1F; color: #F85149; }
.rule-chip {
    display: inline-block;
    background-color: #21262D;
    border: 1px solid #30363D;
    border-radius: 8px;
    padding: 8px 14px;
    margin: 4px 6px 4px 0;
    font-size: 14px;
}
.auth-title { text-align: center; margin-bottom: 0; }
.auth-sub { text-align: center; color: #8B949E; margin-bottom: 1.5rem; }
section[data-testid="stSidebar"] {
    border-right: 1px solid #30363D;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ====================================================================
# API helpers (all calls send the login token)
# ====================================================================
def auth_headers():
    return {"Authorization": "Bearer " + st.session_state.get("token", "")}


def force_logout(message=None):
    for key in ("token", "user", "history"):
        st.session_state.pop(key, None)
    if message:
        st.session_state["login_notice"] = message
    st.rerun()


def api(method, path, **kwargs):
    """Authenticated request. Logs the user out automatically if the token expired."""
    response = requests.request(method, API_BASE + path, headers=auth_headers(),
                                timeout=5, **kwargs)
    if response.status_code == 401:
        force_logout("Your session expired. Please log in again.")
    if not response.ok:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise requests.exceptions.RequestException(str(detail))
    return response.json()


def call_evaluate(payload):
    return api("POST", "/evaluate", json=payload)


def get_config():
    return api("GET", "/config")


def update_config(payload):
    return api("POST", "/config", json=payload)


# ====================================================================
# LOGIN / SIGN UP PAGE
# ====================================================================
def public_post(path, payload):
    """Unauthenticated call (login/signup). Returns (ok, data_or_message)."""
    try:
        r = requests.post(API_BASE + path, json=payload, timeout=5)
    except requests.exceptions.ConnectionError:
        return False, "Could not connect to the FastAPI server at 127.0.0.1:8000. Is uvicorn running?"
    except requests.exceptions.RequestException as exc:
        return False, "Request failed: " + str(exc)
    try:
        body = r.json()
    except ValueError:
        return False, r.text
    if r.ok:
        return True, body
    detail = body.get("detail", "Request failed")
    if isinstance(detail, list):  # pydantic validation errors
        detail = "; ".join(str(d.get("msg", d)) for d in detail)
    return False, detail


def login_page():
    _, mid, _ = st.columns([1, 1.4, 1])
    with mid:
        st.markdown("<h1 class='auth-title'>Fraud Rule Engine</h1>", unsafe_allow_html=True)
        st.markdown("<p class='auth-sub'>Sign in to access the platform</p>",
                    unsafe_allow_html=True)

        notice = st.session_state.pop("login_notice", None)
        if notice:
            st.warning(notice)

        tab_login, tab_signup = st.tabs(["Login", "Sign up"])

        with tab_login:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                login_clicked = st.form_submit_button("Log in", use_container_width=True,
                                                      type="primary")
            if login_clicked:
                if not username or not password:
                    st.error("Enter both username and password.")
                else:
                    ok, data = public_post("/auth/login",
                                           {"username": username, "password": password})
                    if ok:
                        st.session_state["token"] = data["token"]
                        st.session_state["user"] = data["user"]
                        st.session_state["history"] = []
                        st.rerun()
                    else:
                        st.error(data)

        with tab_signup:
            with st.form("signup_form"):
                s_user = st.text_input("Username", key="su_user")
                s_email = st.text_input("Email", key="su_email")
                s_pw = st.text_input("Password", type="password", key="su_pw",
                                     help="8+ chars with upper, lower and a digit")
                s_pw2 = st.text_input("Confirm password", type="password", key="su_pw2")
                signup_clicked = st.form_submit_button("Create account", use_container_width=True)
            if signup_clicked:
                if s_pw != s_pw2:
                    st.error("Passwords do not match.")
                else:
                    ok, data = public_post("/auth/signup",
                                           {"username": s_user, "email": s_email,
                                            "password": s_pw})
                    if ok:
                        st.success(data["message"])
                    else:
                        st.error(data)


# ---- Gate: nothing below runs unless the user is logged in ----
if "token" not in st.session_state:
    login_page()
    st.stop()

user = st.session_state["user"]
is_admin = user["role"] == "admin"

if "history" not in st.session_state:
    st.session_state.history = []


# ====================================================================
# UI helpers
# ====================================================================
def metric_card(value, label):
    html = '<div class="metric-card"><h2>' + str(value) + '</h2><p>' + label + '</p></div>'
    st.markdown(html, unsafe_allow_html=True)


def decision_badge(decision):
    css_class = "badge-approve"
    if decision == "REVIEW":
        css_class = "badge-review"
    elif decision == "DECLINE":
        css_class = "badge-decline"
    html = '<span class="decision-badge ' + css_class + '">' + decision + '</span>'
    st.markdown(html, unsafe_allow_html=True)


# ====================================================================
# Sidebar
# ====================================================================
pages = ["Evaluator", "Dashboard", "History", "Rule Management"]
if is_admin:
    pages.append("User Management")

with st.sidebar:
    st.markdown("## Fraud Rule Engine")
    st.caption("Real-time transaction risk scoring")
    st.markdown("---")
    page = st.radio("Navigate", pages, label_visibility="collapsed")
    st.markdown("---")
    st.markdown("**" + user["username"] + "**  \n`" + user["role"] + "`")
    if st.button("Log out", use_container_width=True):
        force_logout()
    st.caption("Backend: FastAPI @ localhost:8000")


# ---------------- PAGE: Evaluator ----------------
if page == "Evaluator":
    st.title("Transaction Evaluator")
    st.caption("Submit a transaction to score it against the live rule engine.")

    with st.container(border=True):
        with st.form("transaction_form"):
            col1, col2 = st.columns(2)

            with col1:
                transaction_id = st.text_input("Transaction ID", value="txn_001")
                card_id = st.text_input("Card ID", value="card_123")
                amount = st.number_input("Amount", min_value=0.0, value=100.0, step=10.0)
                currency = st.selectbox("Currency", ["USD", "EUR", "GBP", "INR"])

            with col2:
                merchant_id = st.text_input("Merchant ID", value="merchant_abc")
                mcc = st.text_input("MCC", value="5812")
                country = st.text_input("Country", value="US")
                channel = st.selectbox("Channel", ["card_present", "ecommerce", "atm"])

            submitted = st.form_submit_button("Evaluate Transaction", use_container_width=True, type="primary")

    if submitted:
        payload = {
            "transaction_id": transaction_id,
            "card_id": card_id,
            "amount": amount,
            "currency": currency,
            "merchant_id": merchant_id,
            "mcc": mcc,
            "country": country,
            "channel": channel,
        }

        try:
            result = call_evaluate(payload)
            decision = result["decision"]
            score = result["total_score"]

            st.markdown("### Result")
            res_col1, res_col2 = st.columns([1, 3])
            with res_col1:
                decision_badge(decision)
            with res_col2:
                st.write("Risk score: " + str(score))

            if result["triggered_rules"]:
                st.markdown("#### Triggered Rules")
                for rule in result["triggered_rules"]:
                    chip = rule["rule_name"] + "  -  score " + str(rule["score"])
                    st.markdown('<div class="rule-chip">' + chip + '</div>', unsafe_allow_html=True)
                    st.caption(rule["reason"])
            else:
                st.info("No rules triggered - transaction looks clean.")

            record = dict(payload)
            record["decision"] = decision
            record["total_score"] = score
            record["evaluated_by"] = user["username"]
            st.session_state.history.append(record)

        except requests.exceptions.ConnectionError:
            st.error("Could not connect to the FastAPI server at 127.0.0.1:8000. Is uvicorn running?")
        except requests.exceptions.RequestException as exc:
            st.error("Request failed: " + str(exc))


# ---------------- PAGE: Dashboard ----------------
elif page == "Dashboard":
    st.title("Dashboard")

    if len(st.session_state.history) == 0:
        st.info("No transactions evaluated yet this session. Go to Evaluator to test some first.")
    else:
        df = pd.DataFrame(st.session_state.history)

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card(len(df), "Total Evaluated")
        with c2:
            metric_card(int((df["decision"] != "APPROVE").sum()), "Flagged")
        with c3:
            metric_card(round(df["total_score"].mean(), 2), "Avg Risk Score")
        with c4:
            flagged_rate = round((df["decision"] != "APPROVE").mean() * 100, 1)
            metric_card(str(flagged_rate) + "%", "Flag Rate")

        st.markdown("")
        chart_col1, chart_col2 = st.columns(2)
        color_map = {"APPROVE": "#3FB950", "REVIEW": "#D29922", "DECLINE": "#F85149"}

        with chart_col1:
            st.markdown("#### Decisions Breakdown")
            decision_counts = df["decision"].value_counts().reset_index()
            decision_counts.columns = ["decision", "count"]
            fig = px.pie(decision_counts, names="decision", values="count", hole=0.55,
                         color="decision", color_discrete_map=color_map)
            fig.update_layout(showlegend=True, margin=dict(t=10, b=10, l=10, r=10),
                               paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                               font_color="#E6EDF3")
            st.plotly_chart(fig, use_container_width=True)

        with chart_col2:
            st.markdown("#### Risk Score Over Time")
            df_indexed = df.reset_index().rename(columns={"index": "transaction_number"})
            fig2 = px.line(df_indexed, x="transaction_number", y="total_score", markers=True)
            fig2.update_traces(line_color="#4F46E5")
            fig2.update_layout(margin=dict(t=10, b=10, l=10, r=10),
                                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                font_color="#E6EDF3")
            st.plotly_chart(fig2, use_container_width=True)

        st.markdown("#### Amount vs Risk Score")
        fig3 = px.scatter(df, x="amount", y="total_score", color="decision",
                           color_discrete_map=color_map, size_max=10)
        fig3.update_layout(margin=dict(t=10, b=10, l=10, r=10),
                            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                            font_color="#E6EDF3")
        st.plotly_chart(fig3, use_container_width=True)


# ---------------- PAGE: History ----------------
elif page == "History":
    st.title("Transaction History")

    if len(st.session_state.history) == 0:
        st.info("No transactions evaluated yet this session.")
    else:
        df = pd.DataFrame(st.session_state.history)
        st.dataframe(df, use_container_width=True, hide_index=True)

        col_a, col_b = st.columns([1, 5])
        with col_a:
            if st.button("Clear History", type="secondary"):
                st.session_state.history = []
                st.rerun()
        with col_b:
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("Download CSV", csv, "transaction_history.csv", "text/csv")


# ---------------- PAGE: Rule Management ----------------
elif page == "Rule Management":
    st.title("Rule Management")
    if is_admin:
        st.caption("Adjust thresholds live - changes apply immediately to new evaluations, no restart needed.")
    else:
        st.info("You have read-only access. Only admins can change rules.")

    config_load_error = None
    current = None
    try:
        current = get_config()
    except requests.exceptions.ConnectionError:
        config_load_error = "Could not connect to the FastAPI server at 127.0.0.1:8000. Is uvicorn running?"
    except requests.exceptions.RequestException as exc:
        config_load_error = "Could not load current config: " + str(exc)

    if config_load_error:
        st.error(config_load_error)

    if current is not None:
        with st.container(border=True):
            with st.form("config_form"):
                amount_threshold = st.slider(
                    "Amount Threshold ($)", 100.0, 10000.0,
                    float(current["amount_threshold"]), step=100.0, disabled=not is_admin
                )
                review_threshold = st.slider(
                    "Review Score Threshold", 0.5, 10.0,
                    float(current["review_threshold"]), step=0.5, disabled=not is_admin
                )
                decline_threshold = st.slider(
                    "Decline Score Threshold", 1.0, 20.0,
                    float(current["decline_threshold"]), step=0.5, disabled=not is_admin
                )

                config_submitted = st.form_submit_button(
                    "Update Rules", use_container_width=True, type="primary",
                    disabled=not is_admin
                )

        if config_submitted and is_admin:
            new_config = {
                "amount_threshold": amount_threshold,
                "review_threshold": review_threshold,
                "decline_threshold": decline_threshold,
            }
            try:
                updated = update_config(new_config)
                st.success("Rules updated successfully - new thresholds are live.")
                st.json(updated)
            except requests.exceptions.RequestException as exc:
                st.error("Update failed: " + str(exc))


# ---------------- PAGE: User Management (admin only) ----------------
elif page == "User Management" and is_admin:
    st.title("User Management")
    st.caption("Create-by-signup, then promote, reset or remove accounts here.")

    try:
        users = api("GET", "/users")
    except requests.exceptions.RequestException as exc:
        st.error("Could not load users: " + str(exc))
        st.stop()

    udf = pd.DataFrame(users)
    udf["created_at"] = pd.to_datetime(udf["created_at"], unit="s").dt.strftime("%Y-%m-%d %H:%M")
    st.dataframe(udf, use_container_width=True, hide_index=True)

    st.markdown("#### Edit a user")
    others = [u for u in users if u["id"] != user["id"]]
    if not others:
        st.info("No other users yet.")
    else:
        selected = st.selectbox("User", others,
                                format_func=lambda u: u["username"] + " (" + u["role"] + ")")
        c1, c2, c3 = st.columns(3)

        with c1:
            roles = ["admin", "analyst"]
            new_role = st.selectbox("Role", roles, index=roles.index(selected["role"]))
            if st.button("Update role", use_container_width=True):
                try:
                    api("PUT", "/users/" + str(selected["id"]) + "/role", json={"role": new_role})
                    st.rerun()
                except requests.exceptions.RequestException as exc:
                    st.error(str(exc))

        with c2:
            new_pw = st.text_input("New password", type="password")
            if st.button("Reset password", use_container_width=True):
                try:
                    api("PUT", "/users/" + str(selected["id"]) + "/password",
                        json={"new_password": new_pw})
                    st.success("Password reset.")
                except requests.exceptions.RequestException as exc:
                    st.error(str(exc))

        with c3:
            st.write("")
            st.write("")
            if st.button("Delete user", type="primary", use_container_width=True):
                try:
                    api("DELETE", "/users/" + str(selected["id"]))
                    st.rerun()
                except requests.exceptions.RequestException as exc:
                    st.error(str(exc))