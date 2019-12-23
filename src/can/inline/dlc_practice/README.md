# Smartest version: Uses the additional dlc bits to encode padding length.
This version relies on the CAN-controller driver to be adapted. For the Microchip MCP2515,
the file mcp251x.c contains an adapted of the linux driver for this chip.
To compile, the most easy (yet not that fast) variant is to 
download the linux kernel and configure it according to the system's needs (or existing configuration),
and replacing the `drivers/net/can/mcp251x.c` file before building by the one supplied here.
`mcp251x.c_oneshot` contains an untested variant using the one-shot mode of the MCP2515 (all retransmissions disabled)