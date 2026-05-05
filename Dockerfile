# IoT Deception Honeypot - Simulates a Medical IoT Device
# Base: Official Cowrie SSH/Telnet Honeypot
FROM cowrie/cowrie:latest

# Copy custom configuration files
COPY docker/cowrie.cfg /cowrie/etc/cowrie.cfg
COPY docker/userdb.txt /cowrie/etc/userdb.txt

# Copy fake medical device filesystem
COPY docker/honeyfs/ /cowrie/honeyfs/

# Expose SSH (2222) and Telnet (2223) honeypot ports
EXPOSE 2222 2223
