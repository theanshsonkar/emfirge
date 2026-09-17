# ── STAGE 1: BASE IMAGE ───────────────────────────────────────────
# We start from an official Python 3.11 image on Linux
# 'slim' means it's a minimal Linux install — smaller and faster
# Think of this as: "start with a clean Linux machine that has Python 3.11 ready"
FROM python:3.11-slim

# ── STAGE 2: WORKING DIRECTORY ────────────────────────────────────
# Create a folder called /app inside the container
# All our code will live here
# Think of this as: "cd into /app, create it if it doesn't exist"
WORKDIR /app

# ── STAGE 3: INSTALL DEPENDENCIES ────────────────────────────────
# We copy requirements.txt FIRST before copying any code
# Why? Docker caches each step. If requirements.txt hasn't changed,
# Docker skips reinstalling packages on the next build — saving minutes
# This is called "layer caching" — a Docker best practice
COPY requirements.txt .

# Now install all packages from requirements.txt
# --no-cache-dir means don't store install cache — keeps image smaller
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir anthropic PyGithub cryptography && \
    pip uninstall -y google-generativeai && \
    pip install --no-cache-dir google-genai==1.47.0

# ── STAGE 4: COPY APPLICATION CODE ───────────────────────────────
# Now copy everything else — all your Python files
# We do this AFTER installing packages so code changes don't
# trigger a full package reinstall on every build
COPY . .

# ── STAGE 5: SECURITY — NON ROOT USER ────────────────────────────
# By default Docker runs as root (admin) inside the container
# That's a security risk — if someone breaks into the container
# they'd have full root access
# We create a normal user called 'appuser' and switch to it
RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

# ── STAGE 6: EXPOSE PORT ──────────────────────────────────────────
# Tell Docker our app listens on port 8000
# This doesn't open the port yet — it's just documentation
# The actual port mapping happens when you run the container
EXPOSE 8000

# ── STAGE 7: START THE APP ───────────────────────────────────────
# This command runs when the container starts
# It's exactly the same as running locally but without --reload
# --reload is for development only, not for containers
# --host 0.0.0.0 means "accept connections from outside the container"
# Without 0.0.0.0 the app would only be reachable from inside the container
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]