# CRYPTOcan
Code for a minimalistic, backward-compatible, and failure resistant CAN-bus encryption

## Different Variants
`src/can/inline/dlc`
This variant uses an modified DLC (Data length code) to encode the length of the padding.
See the README.md for more info on the 
`src/can/inline/ignored`
This variant simply pads the payload with zeroes, and is therefore not fully backwards compatible.
However, this can be used when upper layer protocols don't need to know the length of received can frames
and handle them in a completely predefined manner (e.g. make no difference between `0xFF` and `0xFF00000000000000`)
`src/can/splitting`
This variant uses AES to encrypt CAN frames and always sends two encrypted frames for one plain frame.
`src/can/stream`
This variant uses the ChaCha20 Streamcipher to encrypt and decrypt CAN frames.
`src/can/isobus`
These are some tools to parse ISOBUS frames after using the 'inline-ignored' variant from above, to verify
the decryption is set up correct, or to gather interesting data from ISOBUS-networks.
`src/simulate.c`
CAN-forwarder which drops or reorders frames with a given probability.

All variants (except isobus/partial) contain hardcoded Keys for encryption, which is of course not suitable for any real scenario.
To use them in a production system, some sort of Key distribution needs to be built.
Also, please note that most examples are configurable to either use ECB-mode (which should be strictly avoided!) or CBC-mode,
which is acceptable but requires the key distribution system to regularly change keys (see e.G. [sweet32](https://sweet32.info) for more information about key renewal intervals)
## Setup
Alle Examples rely on SocketCAN (and therefore a Linux OS) to be installed and a CAN-Controller to be set up.
The CAN interfaces can be enabled using the following commands (assuming `can0` and `can1` to be present):
```
    ip link set can0 type can bitrate 250000 
    ip link set can1 type can bitrate 250000
    ip link set up can0
    ip link set up can1
```
# cryptocan
