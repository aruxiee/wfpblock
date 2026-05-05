# wfpblock
Simple network silencer using Rust &amp; WFP. Bypasses user-mode restrictions to block specific IPs on port 443 with max kernel priority ($2^{64}-1$). Persistent filtering, deceptive protocol handling (blocks HTTPS while allowing Ping), and multi-target support.
