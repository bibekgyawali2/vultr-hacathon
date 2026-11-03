# The disposable detonation environment. One container per job, torn down after.
# Kept minimal: node, python, pip, strace, and an unprivileged user.
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv strace ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && pip install --break-system-packages --no-cache-dir --quiet pip==24.3.1 \
    && useradd -m -u 10001 -s /bin/bash sandbox

COPY runner.py /opt/runner.py
RUN chmod 0755 /opt/runner.py

USER sandbox
WORKDIR /work
ENV HOME=/home/sandbox PYTHONUNBUFFERED=1 NPM_CONFIG_UPDATE_NOTIFIER=false
ENTRYPOINT ["python3", "/opt/runner.py"]
