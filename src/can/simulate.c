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
#include <signal.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
char nextBool(double probability) {
    return (rand() / (double)RAND_MAX) < probability;
}
void handle_sig(int signum) {
    signal(SIGPIPE, SIG_DFL);
    raise(SIGPIPE);
}

int main(int argc, char** argv) {
    int inChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    int outChannel = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    struct sockaddr_can addr1;
    struct ifreq ifr1;
    struct sockaddr_can addr2;
    struct ifreq ifr2;
    srand(time(NULL));

    double loss_q = 0;
    double reord_q = 0;

    if(argc >= 5) {
        loss_q = atof(argv[3]);
        reord_q = atof(argv[4]);
    } else {
        printf("Usage: %s interface_in interface_out p_loss p_reorder [secs]\n"
           "Program stops when receiving a magic frame with payload 0xCAFEBABEDEADBEEF,\n"
           "or after [secs] seconds\n"
           , argv[0]);
        return 1;
    }
    if(argc >= 6) {
        signal(SIGALRM, handle_sig);
        alarm(atoi(argv[5]));
    }
    printf("Forwarding Packets from %s to %s, while loosing %f %% and "
           "reordering 2 pakets %f in %% of all packets.\n",
           argv[0], argv[1], loss_q * 100.0f, reord_q * 100.0f);

    if((loss_q > 1.0f || (loss_q < 0.004f && loss_q != 0.0f)) || (reord_q > 1.0f || (reord_q < 0.004f && reord_q != 0.0f))) {
        printf("p_loss and p_q must be between 0.00393 and 1!\n");
        return 1;
    }

    if(inChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", inChannel);
        exit(1);
    }
    if(outChannel < 0) {
        fprintf(stderr, "Couldnt connect: %d\n", outChannel);
        exit(1);
    }
    strcpy(ifr1.ifr_name, argv[1]);
    ioctl(inChannel, SIOCGIFINDEX, &ifr1);
    addr1.can_family = AF_CAN;
    addr1.can_ifindex = ifr1.ifr_ifindex;
    bind(inChannel, (struct sockaddr*)&addr1, sizeof(addr1));

    strcpy(ifr2.ifr_name, argv[2]);
    ioctl(outChannel, SIOCGIFINDEX, &ifr2);
    addr2.can_family = AF_CAN;
    addr2.can_ifindex = ifr2.ifr_ifindex;
    bind(outChannel, (struct sockaddr*)&addr2, sizeof(addr2));

    struct can_frame last;
    int doSwap = 0;
    struct can_frame cipher;
    int recv_l;
    while(1) {
        char magic[] = {0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF};
        if(memcmp(cipher.data, magic, 8) == 0) {
            break;
        }
        if(doSwap == 2) { // we dont need to receive!
            recv_l = 16;
            memcpy(&cipher, &last, sizeof(struct can_frame));
            doSwap = 3;
        } else {
            if(doSwap == 1)
                doSwap++;
            recv_l = recv(inChannel, &cipher, sizeof(cipher), 0);
        }
        if(recv_l > 0) {
            if(nextBool(loss_q))
                continue; // if loss, simply continue
            if(!doSwap && nextBool(reord_q)) {
                memcpy(&last, &cipher, sizeof(struct can_frame));
                doSwap = 1; // if swap, save & continue
                continue;
            }
            int res = write(outChannel, &cipher, sizeof(struct can_frame));
            if(doSwap == 3)
                doSwap = 0;
        }
    }
}
