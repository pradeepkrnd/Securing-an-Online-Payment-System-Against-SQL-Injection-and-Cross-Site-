MSCS-535 Project 3 - Secure Online Payment: reference implementation
===================================================================

Files
  secure_payment_demo.py   Python implementation of the paper's pseudocode, with a built-in self-check
  test_secure_payment.py   unittest suite (14 tests) for the SQL injection and XSS controls

Requirements
  Python 3.8 or newer. Standard library only (sqlite3, html, json, re, secrets, decimal, urllib).
  No pip installs needed.

Run (Linux server over PuTTY)
  mkdir -p ~/pradeepk && cd ~/pradeepk
  # copy both .py files here (e.g. with WinSCP or pscp), then:
  python3 --version
  python3 secure_payment_demo.py
  python3 -m unittest -v test_secure_payment.py

Expected
  secure_payment_demo.py ends with "Summary: 15 passed, 0 failed"
  the unittest run ends with "Ran 14 tests ... OK"

Note
  get_payment_UNSAFE() is intentionally vulnerable and exists only to show the
  attack succeeding against string concatenation. Do not reuse it.
