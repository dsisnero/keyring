# Dockerfile for testing Linux backend with GNOME Keyring
FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    gnupg2 \
    software-properties-common \
    git \
    build-essential \
    libssl-dev \
    libxml2-dev \
    libyaml-dev \
    libgmp-dev \
    libevent-dev \
    libpcre3-dev \
    # Secret Service / libsecret
    libsecret-1-0 \
    libsecret-1-dev \
    # GNOME Keyring for Secret Service
    gnome-keyring \
    # D-Bus for Secret Service communication
    dbus \
    dbus-x11 \
    # Utilities
    vim \
    less \
    && rm -rf /var/lib/apt/lists/*

# Install Crystal
RUN curl -fsSL https://crystal-lang.org/install.sh | bash

# Verify Crystal installation
RUN crystal --version

# Set up workspace
WORKDIR /workspace

# Set up D-Bus session bus (required for GNOME Keyring)
ENV DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus

# Create script to start D-Bus and GNOME Keyring
RUN echo '#!/bin/bash\n\
set -e\n\
# Create run directory\n\
mkdir -p /run/user/1000\n\
chmod 700 /run/user/1000\n\
# Start D-Bus daemon\n\
dbus-daemon --session --address=$DBUS_SESSION_BUS_ADDRESS --nofork --nopidfile --syslog-only &\n\
DBUS_PID=$!\n\
sleep 1\n\
# Unlock keyring with empty password for testing\n\
echo -n "" | gnome-keyring-daemon --unlock\n\
# Start GNOME Keyring\n\
gnome-keyring-daemon --start --components=secrets &\n\
KEYRING_PID=$!\n\
sleep 1\n\
# Run command\n\
"$@"\n\
# Cleanup\n\
kill $KEYRING_PID $DBUS_PID 2>/dev/null || true\n\
' > /usr/local/bin/with-keyring && chmod +x /usr/local/bin/with-keyring

# Default command: run tests
CMD ["with-keyring", "crystal", "spec"]

# For interactive development:
# docker run -it --rm -v $(pwd):/workspace keyring-linux-test bash
# Then run: with-keyring crystal spec
