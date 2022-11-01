# pcap-stats

Generate simple, anonymous traffic statistics from a pcap file.

# Dependencies

Assumes a Linux environment. In particular, uses the standard Linux headers for packet parsing (see ``parse_headers.h'').

Requires some c++ compiler, make, and libpcap which is available through most package managers (something like ``libpcap-dev'' on debian systems).
A nix environment is included.

# Building

Should compile with a simple ``make''
