# Setup

1. Install dependencies. They are compressed files under `lib/` directory. Installing usually consists of `cd`ing into the uncompressed library directory and running `./configure`, then `make` and finally `make install` (the last command may be `sudo make install`).
2. Run `bash compile.sh`. This will produce the `nfqueue.out` executable and configure its permissions (CAP_NET_ADMIN capability).
3. Run `bash insert-rule.sh`, which will insert rules in 2 chains of the `iptables` module, which essentially state that "all traffic should be handled by our nfqueue executable". *NOTE: This implies all network traffic will be intercepted by the executable, which must be running. If the `nfqueue.out` program is not running, networking will not work.*

The changes to `iptables` can be undone via `bash remove-rule.sh`. This is so that normal networking can be restored.

# Execution

As of the time of writing, running `nfqueue.out` will print information about all packets both arriving and exiting the machine.