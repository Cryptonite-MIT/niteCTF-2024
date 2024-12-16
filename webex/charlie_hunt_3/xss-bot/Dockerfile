FROM gcr.io/kctf-docker/challenge@sha256:eb0f8c3b97460335f9820732a42702c2fa368f7d121a671c618b45bbeeadab28

# Use non-interactive mode for apt-get to reduce potential hanging during builds
ARG DEBIAN_FRONTEND=noninteractive

# Install required dependencies
RUN apt-get update && apt-get install -y \
    gnupg2 \
    wget \
    ca-certificates \
    curl

# Add NodeSource repository for latest Node.js LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -

# Install Chrome and Node.js dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-liberation \
    libappindicator3-1 \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libc6 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libexpat1 \
    libfontconfig1 \
    libgbm1 \
    libgcc1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libstdc++6 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxshmfence1 \
    libxss1 \
    libxtst6 \
    lsb-release \
    nodejs \
    && rm -rf /var/lib/apt/lists/*

# Create and set permissions for Chrome user data directory
RUN mkdir /tmp/chrome-userdata && chmod o+rwx /tmp/chrome-userdata

# Set up user and working directory
USER user
WORKDIR /home/user/

# Install Puppeteer with the latest Node.js
RUN npm install puppeteer

# Copy bot script
COPY bot_pow.js .
COPY pow.js .

# Command to run the bot
CMD while true; do \
    /usr/bin/node /home/user/bot_pow.js ${PORT:-1337}; \
    done

