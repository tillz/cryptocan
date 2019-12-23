/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
#include "../../xtea.h"
#include <errno.h>
#include <inttypes.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

void xor
    (uint8_t * srcdest, const uint8_t* summand, uint8_t len) {
        for(int i = 0; i < len; i++) {
            srcdest[i] ^= summand[i];
        }
    }

    int main(int argc, char** argv) {
    int plainChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    int cipherChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    struct sockaddr_can addr;
    struct ifreq ifr;

    uint8_t last_data[8] = {0};
    int do_cbc = 0;

    // enable CBC mode
    if(argc > 1 && strcmp(argv[1], "cbc") == 0) {
        do_cbc = 1;
        // an IV can be given as single arguments
        if(argc >= 10) {
            for(int i = 0; i < 8; i++) {
                last_data[i] = atoi(argv[i + 2]);
            }
        }
    }
    uint8_t orig_cbc[8];
    memcpy(orig_cbc, last_data, 8);
    if(plainChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", plainChannel);
    }
    if(cipherChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", cipherChannel);
    }

    // Channel where plain messages are being received
    strcpy(ifr.ifr_name, (getenv("CAN_RX") ? getenv("CAN_RX") : "can0"));
    ioctl(plainChannel, SIOCGIFINDEX, &ifr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    bind(plainChannel, (struct sockaddr*)&addr, sizeof(addr));

    strcpy(ifr.ifr_name, (getenv("CAN_TX") ? getenv("CAN_TX") : "can1"));
    ioctl(cipherChannel, SIOCGIFINDEX, &ifr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    bind(cipherChannel, (struct sockaddr*)&addr, sizeof(addr));

    // convert key
    char kRaw[] = {0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e};
    uint32_t k[4] = {0};
    for(int i = 0; i < 16; i++) {
        k[i / 4] |= kRaw[i] << 8 * ((i % 4));
    }

    struct can_frame plain;
    struct can_frame cipher;
    int recv_l;
    while(1) {
        recv_l = recv(plainChannel, &plain, sizeof(plain), 0);
        if(recv_l > 0) {
            char magic[] = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
            if(memcmp(plain.data, magic, 8) == 0) {
                write(cipherChannel, &plain, sizeof(struct can_frame));
                memcpy(last_data, orig_cbc, 8);
                continue;
            }
            uint32_t can_id = plain.can_id & 0b00011111111111111111111111111111;
            fprintf(stderr, "received frame. [%d]/[%d], %02x %02x %02x %02x %02x %02x %02x %02x\n", plain.can_dlc, plain.__res0, plain.data[0], plain.data[1], plain.data[2], plain.data[3], plain.data[4], plain.data[5], plain.data[6], plain.data[7]);
            memset(cipher.data, 0, 8);
            if(plain.can_dlc > 0) {
                uint32_t t[] = {0, 0};
                memcpy(t, plain.data, 4);
                memcpy(t + 1, plain.data + 4, 4);
                if(do_cbc) {
                    xor((uint8_t*)t, last_data, 8);
                }
                encipher(64, t, k);
                if(do_cbc) {
                    memcpy(last_data, (uint8_t*)t, 8);
                }
                memcpy(cipher.data, t, 4);
                memcpy(cipher.data + 4, t + 1, 4);
                cipher.can_dlc = 8;
                fprintf(stderr, "Encrypted Frame to send: [%d]/[%d], %02x %02x %02x %02x %02x %02x %02x %02x\n", cipher.can_dlc, cipher.__res0, cipher.data[0], cipher.data[1], cipher.data[2], cipher.data[3], cipher.data[4], cipher.data[5], cipher.data[6], cipher.data[7]);
            } else {
                cipher.can_dlc = 0;
            }
            cipher.can_id = plain.can_id;
            int res = write(cipherChannel, &cipher, sizeof(struct can_frame));
            fprintf(stderr, "write ret: %d, %d, %s\n", res, errno, strerror(errno));
        }
        fprintf(stderr, "asd\n");
    }
}

