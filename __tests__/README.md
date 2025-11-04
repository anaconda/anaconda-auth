**Anaconda Hub CLI + Playwright Automation**

This repository provides end-to-end automation for the Anaconda Hub login flow, combining the Anaconda CLI, Playwright API, and browser interactions. It covers:

* OAuth login via API + browser
* CLI-driven login (`anaconda auth login`) against an already authenticated session
* Verification of the success banner and URL path

---

## 📋 Prerequisites

1. **Python 3.9+** (using `venv`) or **Miniconda/Anaconda** (recommended for isolating dependencies).

2. **Playwright** browsers:

   ```bash
   pip install playwright
   playwright install
   ```

3. **Python dependencies**:

   ```bash
   pip install -r requirements-pip.txt
   pip install -e .
   ```


---

## ⚙️ Configuration

* `.env` should live next to `conftest.py` and be loaded automatically.
* Tests use pytest fixtures defined in `conftest.py`:

  * **ensureConda**: installs or locates `conda` on PATH.
  * **api\_request\_context**: Playwright API context against `ANACONDA_API_BASE`.
  * **urls** / **credentials**: pulled from `.env`.

---

## 🚀 Running the tests

### All tests (headed)

```bash
pytest -q --headed
```

### Run only Playwright login flow

```bash
pytest -q tests/test_anaconda_login.py --headed
```

### Run only CLI‑flow extension

```bash
pytest -q tests/test_anaconda_login_cli_flow.py --headed
```

> Use `-q` for concise output, `--headed` to see the browser.

---

## 🔍 Test coverage

* **`test_anaconda_login.py`**: API → browser login + banner + URL assertion
* **`test_anaconda_login_cli_flow.py`**: full end‑to‑end CLI+browser flow, capturing and completing the OAuth handshake

---

## ⚠️ Tips

* If you change environment variables, restart your test session or shell.
* To debug CLI flow, watch the console logs: each step prints subprocess stdout/stderr.
* Ensure no other process is using the OAuth callback port (default or via `ANACONDA_OAUTH_CALLBACK_PORT`).

---

Happy testing!
