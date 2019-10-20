sudo iptables -A INPUT -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0