FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    tzdata \
    nginx \
    openssh-server \
    supervisor \
    openssl \
    curl \
    net-tools \
    iproute2 \
    iputils-ping \
    tcpdump \
    nano \
    bind9 \ 
    dnsutils \
    ntp \ 
    coturn \
    bash-completion && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone &&\
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Create log and PID directories with correct permissions
RUN mkdir -p /var/log/nginx /var/log/sshd /var/log/supervisor /run/nginx /run/sshd /run/supervisor && \
    chown www-data:www-data /var/log/nginx /usr/share/nginx/html && \
    chown root:root /var/log/supervisor /run/supervisor && \
    chmod 755 /var/log/nginx /var/log/sshd /var/log/supervisor /run/nginx /run/sshd /run/supervisor && \
    touch /var/log/supervisor/supervisord.log && \
    chmod 644 /var/log/supervisor/supervisord.log

# Configure bash completion and terminal
RUN echo "source /etc/bash.bashrc" > /root/.bashrc && \
    echo "export TERM=xterm-256color" >> /root/.bashrc

# Generate SSL certificate
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx.key \
    -out /etc/nginx/ssl/nginx.crt \
    -subj "/C=CN/ST=State/L=City/O=Organization/OU=Unit/CN=localhost" && \
    chmod 644 /etc/nginx/ssl/nginx.crt /etc/nginx/ssl/nginx.key

# Copy configuration files
COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
RUN chown root:root /etc/nginx/nginx.conf /etc/supervisor/conf.d/supervisord.conf && \
    chmod 644 /etc/nginx/nginx.conf /etc/supervisor/conf.d/supervisord.conf

# Configure SSH
RUN echo "root:root" | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    useradd -m -s /bin/bash admin && \
    dd if=/dev/urandom of=/tmp/dummy_file bs=1M count=2 && \
    echo "admin:admin" | chpasswd

# Set default webpage
RUN dd if=/dev/urandom of=/var/www/html/smallfile.html bs=50K count=1 && \
    dd if=/dev/urandom of=/var/www/html/mediumfile.pdf bs=1M count=2 && \
    dd if=/dev/urandom of=/var/www/html/largefile.bin bs=1M count=10 && \
    echo "<h1>Welcome to IDC Test Environment</h1><p>Services: HTTP, HTTPS, SSH</p>" > /var/www/html/index.html && \
    chown www-data:www-data /var/www/html/* && \
    chmod 644 /var/www/html/*

# Disable IPv6
RUN echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf


# Copy and set executable entrypoint
COPY ntp.conf /etc/ntp.conf
COPY turnserver.conf /etc/turnserver.conf
# Copy Bind9 configs
COPY named.conf.options /etc/bind/named.conf.options
COPY named.conf.local /etc/bind/named.conf.local
COPY db.lfa.com /etc/bind/db.lfa.com
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

EXPOSE 80 443 22 53 123 3478

CMD ["/entrypoint.sh"]