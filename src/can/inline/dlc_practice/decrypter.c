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

void xor (uint8_t * srcdest, const uint8_t* summand, uint8_t len) {
    for(int i = 0; i < len; i++) {
        srcdest[i] ^= summand[i];
    }
} int main(int argc, char** argv) {
    int cipherChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    int plainChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    int do_cbc = 0;
    uint8_t last_data[8] = {0};
    struct sockaddr_can addr1;
    struct ifreq ifr1;
    struct sockaddr_can addr2;
    struct ifreq ifr2;

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

    if(cipherChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", cipherChannel);
    }
    if(plainChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", plainChannel);
    }

    // Channel where encrypted messages are being received
    strcpy(ifr1.ifr_name, (getenv("CAN_RX") ? getenv("CAN_RX") : "can0"));
    ioctl(cipherChannel, SIOCGIFINDEX, &ifr1);
    addr1.can_family = AF_CAN;
    addr1.can_ifindex = ifr1.ifr_ifindex;
    bind(cipherChannel, (struct sockaddr*)&addr1, sizeof(addr1));

    strcpy(ifr2.ifr_name, (getenv("CAN_TX") ? getenv("CAN_TX") : "can1"));
    ioctl(plainChannel, SIOCGIFINDEX, &ifr2);
    addr2.can_family = AF_CAN;
    addr2.can_ifindex = ifr2.ifr_ifindex;
    bind(plainChannel, (struct sockaddr*)&addr2, sizeof(addr2));

    // convert key
    char kRaw[] = {0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e};
    uint32_t k[4] = {0};
    for(int i = 0; i < 16; i++) {
        k[i / 4] |= kRaw[i] << 8 * ((i % 4));
    }

    struct can_frame cipher;
    struct can_frame plain;
    int recv_l;
    while(1) {
        recv_l = recv(cipherChannel, &cipher, sizeof(cipher), 0);
        if(recv_l > 0) {
            uint32_t can_id = cipher.can_id & 0b00011111111111111111111111111111;
            fprintf(stderr, "received frame. [%d]/[%d], %02x %02x %02x %02x %02x %02x %02x %02x\n", cipher.can_dlc, cipher.__res0, cipher.data[0], cipher.data[1], cipher.data[2], cipher.data[3], cipher.data[4], cipher.data[5], cipher.data[6], cipher.data[7]);
            memset(plain.data, 0, 8);
            if(cipher.can_dlc > 0) {
                uint32_t t[] = {0, 0};
                memcpy(t, cipher.data, 4);
                memcpy(t + 1, cipher.data + 4, 4);
                decipher(64, t, k);
                if(do_cbc) {
                    xor((uint8_t*)t, last_data, 8);
                    memcpy(last_data, (uint8_t*)cipher.data, 8);
                }
                memcpy(plain.data, t, 4);
                memcpy(plain.data + 4, t + 1, 4);
                plain.can_dlc = 8 - cipher.__res0;
                fprintf(stderr, "Decrypted Frame to send: [%d]/[%d], %02x %02x %02x %02x %02x %02x %02x %02x\n", plain.can_dlc, plain.__res0, plain.data[0], plain.data[1], plain.data[2], plain.data[3], plain.data[4], plain.data[5], plain.data[6], plain.data[7]);
            } else {
                plain.can_dlc = 0;
            }
            plain.can_id = cipher.can_id;
            int res = write(plainChannel, &plain, sizeof(struct can_frame));
            fprintf(stderr, "write ret: %d, %d, %s\n", res, errno, strerror(errno));
        }
        fprintf(stderr, "asd\n");
    }
}
