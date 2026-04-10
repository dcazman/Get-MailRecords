FROM alpine:3.21
RUN apk add --no-cache \
    nodejs \
    npm \
    curl \
    ca-certificates \
    less \
    ncurses-terminfo-base \
    krb5-libs \
    libgcc \
    libintl \
    libssl3 \
    libstdc++ \
    tzdata \
    userspace-rcu \
    zlib \
    icu-libs \
    bind-tools
RUN curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.6.0/powershell-7.6.0-linux-musl-x64.tar.gz \
    -o /tmp/pwsh.tar.gz && \
    mkdir -p /opt/microsoft/powershell/7 && \
    tar zxf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell/7 && \
    chmod +x /opt/microsoft/powershell/7/pwsh && \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh && \
    rm /tmp/pwsh.tar.gz
WORKDIR /app
COPY gmr.ps1 /app/gmr.ps1
COPY package.json /app/package.json
RUN npm install --omit=dev
COPY server.js /app/server.js
COPY start.sh /start.sh
RUN chmod +x /start.sh
EXPOSE 7777
CMD ["/start.sh"]
