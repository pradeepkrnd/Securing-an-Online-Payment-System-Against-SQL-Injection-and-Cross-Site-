#!/usr/bin/env python3
"""
secure_payment_demo.py
MSCS-535 Project 3 - Reference implementation of the pseudocode in the paper.

Demonstrates, for a small online-payment workflow:
  * SQL injection defenses: allow-list input validation, parameterized
    queries, a fixed column/sort allow-list, generic error handling,
    and storing only a gateway token (never the card number).
  * Cross-site scripting defenses: input allow-listing, context-aware
    output encoding (HTML body, HTML attribute, JavaScript, URL),
    and security headers (Content-Security-Policy, cookie flags).

Standard library only (Python 3.8+). Run:  python3 secure_payment_demo.py
"""

import html
import json
import re
import secrets
import sqlite3
import sys
import urllib.parse
from decimal import Decimal, InvalidOperation

# ---------------------------------------------------------------------------
# 1. Input validation (allow-list) - first line of defense for SQLi and XSS
# ---------------------------------------------------------------------------
ORDER_ID_RE = re.compile(r"^[0-9]{1,10}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,185}\.[A-Za-z]{2,24}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z '\-]{0,59}$")
CURRENCIES = {"USD", "EUR", "GBP"}
SORT_COLUMNS = {"created": "created_at", "amount": "amount"}   # allow-list map
MAX_AMOUNT = Decimal("10000.00")


class ValidationError(ValueError):
    """Raised when a request field fails allow-list validation."""


def validate_order_id(value):
    if not isinstance(value, str) or not ORDER_ID_RE.fullmatch(value):
        raise ValidationError("order_id")
    return int(value)


def validate_amount(value):
    try:
        amount = Decimal(value)
    except (InvalidOperation, TypeError):
        raise ValidationError("amount")
    if amount <= 0 or amount > MAX_AMOUNT or amount.as_tuple().exponent < -2:
        raise ValidationError("amount")
    return amount


def validate_currency(value):
    if value not in CURRENCIES:
        raise ValidationError("currency")
    return value


def validate_email(value):
    if not isinstance(value, str) or not EMAIL_RE.fullmatch(value):
        raise ValidationError("email")
    return value.lower()


def validate_name(value):
    if not isinstance(value, str) or not NAME_RE.fullmatch(value.strip()):
        raise ValidationError("cardholder_name")
    return value.strip()


def validate_sort(value):
    # Identifiers cannot be bound as parameters, so map to a fixed allow-list.
    if value not in SORT_COLUMNS:
        raise ValidationError("sort")
    return SORT_COLUMNS[value]


# ---------------------------------------------------------------------------
# 2. Data layer - parameterized queries only
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE customers (
    customer_id INTEGER PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL
);
CREATE TABLE payments (
    order_id     INTEGER PRIMARY KEY,
    customer_id  INTEGER NOT NULL REFERENCES customers(customer_id),
    amount       TEXT NOT NULL,
    currency     TEXT NOT NULL,
    card_token   TEXT NOT NULL,      -- gateway token, never the PAN
    card_last4   TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def open_db():
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA)
    conn.execute("INSERT INTO customers VALUES (1, 'alice@example.com', 'Alice Doe')")
    conn.execute("INSERT INTO customers VALUES (2, 'bob@example.com', 'Bob Roe')")
    conn.execute("INSERT INTO payments (order_id, customer_id, amount, currency, card_token,"
                 " card_last4, status) VALUES (1001, 1, '49.99', 'USD', 'tok_a1', '4242', 'PAID')")
    conn.execute("INSERT INTO payments (order_id, customer_id, amount, currency, card_token,"
                 " card_last4, status) VALUES (1002, 2, '15.00', 'USD', 'tok_b2', '1881', 'PAID')")
    conn.commit()
    return conn


def get_payment_UNSAFE(conn, customer_id, raw_order_id):
    """DEMONSTRATION ONLY - string concatenation, vulnerable to SQL injection."""
    sql = ("SELECT order_id, amount, status FROM payments WHERE customer_id = "
           + str(customer_id) + " AND order_id = '" + raw_order_id + "'")
    return conn.execute(sql).fetchall()


def get_payment(conn, customer_id, raw_order_id):
    """Secure lookup: validated input + bound parameters + ownership check."""
    order_id = validate_order_id(raw_order_id)
    sql = ("SELECT order_id, amount, status FROM payments "
           "WHERE customer_id = ? AND order_id = ?")
    return conn.execute(sql, (customer_id, order_id)).fetchall()


def list_payments(conn, customer_id, raw_sort):
    column = validate_sort(raw_sort)               # identifier from allow-list
    sql = ("SELECT order_id, amount, status FROM payments "
           "WHERE customer_id = ? ORDER BY " + column + " DESC")
    return conn.execute(sql, (customer_id,)).fetchall()


def tokenize_card(pan):
    """Stand-in for a PCI-compliant gateway: returns a token and last four digits."""
    digits = re.sub(r"\D", "", pan)
    if not 13 <= len(digits) <= 19:
        raise ValidationError("card_number")
    return "tok_" + secrets.token_hex(8), digits[-4:]


def create_payment(conn, customer_id, form):
    amount = validate_amount(form.get("amount"))
    currency = validate_currency(form.get("currency"))
    validate_name(form.get("cardholder_name"))
    token, last4 = tokenize_card(form.get("card_number", ""))
    try:
        with conn:                                   # transaction: commit or roll back
            cur = conn.execute(
                "INSERT INTO payments (customer_id, amount, currency, card_token,"
                " card_last4, status) VALUES (?, ?, ?, ?, ?, 'PENDING')",
                (customer_id, str(amount), currency, token, last4))
        return cur.lastrowid
    except sqlite3.Error:
        # Log details server-side; return a generic message to the client.
        raise RuntimeError("Payment could not be processed.")


# ---------------------------------------------------------------------------
# 3. Output layer - context-aware encoding and security headers (XSS)
# ---------------------------------------------------------------------------
def enc_html(value):
    return html.escape(str(value), quote=True)


def enc_attr(value):
    return html.escape(str(value), quote=True)


def enc_js(value):
    # JSON-encode, then neutralise characters that could close a <script> block.
    s = json.dumps(str(value))
    return s.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def safe_url(value):
    parsed = urllib.parse.urlparse(str(value))
    if parsed.scheme not in ("https",) or not parsed.netloc:
        return "#"
    return enc_attr(value)


def security_headers(nonce):
    return {
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; "
            "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self'"),
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Set-Cookie": "session=<id>; Secure; HttpOnly; SameSite=Strict; Path=/",
    }


def render_receipt(name, order_id, amount, note, return_url):
    nonce = secrets.token_urlsafe(16)
    body = (
        "<h1>Receipt for " + enc_html(name) + "</h1>\n"
        "<p>Order " + enc_html(order_id) + ": $" + enc_html(amount) + "</p>\n"
        "<p>Note: " + enc_html(note) + "</p>\n"
        "<input type=\"hidden\" name=\"note\" value=\"" + enc_attr(note) + "\">\n"
        "<a href=\"" + safe_url(return_url) + "\">Return to store</a>\n"
        "<script nonce=\"" + nonce + "\">var buyer = " + enc_js(name) + ";</script>"
    )
    return security_headers(nonce), body


# ---------------------------------------------------------------------------
# 4. Self-check: run attack strings against the unsafe and safe paths
# ---------------------------------------------------------------------------
def main():
    conn = open_db()
    passed = failed = 0

    def check(label, ok):
        nonlocal passed, failed
        print(("[PASS] " if ok else "[FAIL] ") + label)
        if ok:
            passed += 1
        else:
            failed += 1

    print("=== SQL injection tests (customer_id = 1) ===")
    payload = "1001' OR '1'='1"
    leaked = get_payment_UNSAFE(conn, 1, payload)
    print("UNSAFE query with payload %r returned %d row(s): %s" % (payload, len(leaked), leaked))
    check("Concatenated query is exploitable (expected for the demo)", len(leaked) > 1)

    for attack in ["1001' OR '1'='1", "1001; DROP TABLE payments;--", "1002 UNION SELECT 1,2,3"]:
        try:
            get_payment(conn, 1, attack)
            check("Rejected %r" % attack, False)
        except ValidationError as e:
            check("Rejected %r (field: %s)" % (attack, e), True)

    check("Legitimate own order 1001 is returned", len(get_payment(conn, 1, "1001")) == 1)
    check("Another customer's order 1002 is NOT returned", get_payment(conn, 1, "1002") == [])
    try:
        list_payments(conn, 1, "amount; DROP TABLE payments")
        check("Malicious sort column rejected", False)
    except ValidationError:
        check("Malicious sort column rejected", True)
    check("payments table still exists",
          conn.execute("SELECT count(*) FROM payments").fetchone()[0] >= 2)

    oid = create_payment(conn, 1, {"amount": "25.50", "currency": "USD",
                                   "cardholder_name": "Alice Doe",
                                   "card_number": "4111 1111 1111 1111"})
    row = conn.execute("SELECT card_token, card_last4 FROM payments WHERE order_id = ?",
                       (oid,)).fetchone()
    check("Stored token %s / last4 %s - full card number not stored" % row,
          row[0].startswith("tok_") and "4111111111111111" not in str(row))

    print("\n=== Cross-site scripting tests ===")
    try:
        validate_name("<script>alert(1)</script>")
        check("Script tag rejected in cardholder name", False)
    except ValidationError:
        check("Script tag rejected in cardholder name", True)

    headers, page = render_receipt(
        name="Alice Doe</script><script>alert(1)</script>",
        order_id=1001, amount="49.99",
        note="\"><img src=x onerror=alert(1)>",
        return_url="javascript:alert(document.cookie)")
    print(page)
    check("No executable <script>alert in output", "<script>alert" not in page)
    check("No raw onerror= attribute injection", "<img src=x onerror" not in page)
    check("javascript: URL replaced with '#'", 'href="#"' in page)
    check("CSP header present with nonce", "nonce-" in headers["Content-Security-Policy"])
    check("Session cookie is HttpOnly and Secure",
          "HttpOnly" in headers["Set-Cookie"] and "Secure" in headers["Set-Cookie"])

    print("\nSummary: %d passed, %d failed" % (passed, failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
