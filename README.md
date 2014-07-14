wireshark-stt-dissector
=======================

Wireshark Stateless Transport Tunneling dissector

## Installation guide

* Download source code

```bash
# git clone https://code.wireshark.org/review/wireshark

# git clone https://github.com/rvichery/wireshark-stt-dissector
```

* Add STT dissector to wireshark source

```bash
# cp wireshark-stt-dissector/src/packet-stt.c wireshark/epan/dissectors
```

Edit wireshark/epan/dissectors/Makefile.common, add the following line between packet-stat.c and packet-stun.c:

```
DISSECTOR_SRC = \
...
packet-stats.c     \
packet-stt.c       \
packet-stun.c      \
...
```

Edit wireshark/epan/CMakeLists.txt, add the following line between packet-stat.c and packet-stun.c:

```
set(DISSECTOR_SRC
...
dissectors/packet-stat.c
dissectors/packet-stt.c
dissectors/packet-stun.c
...
```

* Compile wireshark

```
# ./configure
# make
# make install
