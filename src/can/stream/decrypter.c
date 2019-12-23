/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
#include <errno.h>
#include <inttypes.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

void printFrame(char* note, struct can_frame* f) {
    fprintf(stderr, "%s: ID: %ul, Len: [%d]/[%d], %02x %02x %02x %02x %02x %02x %02x %02x\n", note, f->can_id, f->can_dlc, f->__res0, f->data[0], f->data[1], f->data[2], f->data[3], f->data[4], f->data[5], f->data[6], f->data[7]);
}

int main(int argc, char** argv) {
    int cipherChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    int plainChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    struct sockaddr_can addr1;
    struct sockaddr_can addr2;
    struct ifreq ifr1;
    struct ifreq ifr2;

    int sendNonce = 0;
    if(argc > 1) {
        sendNonce = atoi(argv[1]);
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
    // convert key
    // ATTENTION! INSECURE KEY
    char kRaw[] = {0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e, 0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e};
    //     char nonce[crypto_stream_chacha20_NONCEBYTES]={0};
    char nonce[] = {0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e, 0x3e, 0x55, 0x95, 0xa9, 0xe7, 0xb7, 0x64, 0xb9, 0x29, 0x85, 0xea, 0xff, 0x8a, 0x44, 0x8c, 0x0e};
    //     randombytes_buf(nonce, crypto_stream_chacha20_NONCEBYTES);
    // Wir koennen die Nonce noch nicht rueberschicken. Daher (ILLEGAL!!!!!!!)
    // als fest annehmen!
    nonce[crypto_stream_chacha20_NONCEBYTES - 1] = 1;
    uint64_t ctr = 0;

    struct can_frame cipher;
    struct can_frame plain;
    int recv_l;
    while(1) {
        recv_l = recv(cipherChannel, &cipher, sizeof(cipher), 0);
        if(recv_l > 0) {
            char magic[] = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
            if(memcmp(cipher.data, magic, 8) == 0) {
                write(plainChannel, &cipher, sizeof(struct can_frame));
                ctr = 0;
                continue;
            }
            uint32_t can_id = cipher.can_id & 0b00011111111111111111111111111111;
            if(can_id != 12342) {
                if(sendNonce && can_id == 1) {
                    printFrame("Successfully received Nonce:", &cipher);
                    memcpy(nonce, cipher.data, 8);
                    ctr = 0;
                } else {
                    fprintf(stderr, "Ignored packet on wrong id\n");
                }
            } else {
                memset(plain.data, 0, 8);
                printFrame("Received encrypted frame:", &cipher);
                if(cipher.can_dlc > 0) {
                    crypto_stream_chacha20_xor_ic(plain.data, cipher.data, cipher.can_dlc, nonce, ctr, kRaw);
                    ctr += cipher.can_dlc;
                    plain.can_dlc = cipher.can_dlc;
                } else {
                    plain.can_dlc = 0;
                }
                plain.can_id = cipher.can_id;
                printFrame("Decrypted frame to send:", &plain);
                int res = write(plainChannel, &plain, sizeof(struct can_frame));
            }
        }
        fprintf(stderr, "Received\n");
    }
}
