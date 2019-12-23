/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
module.exports = {
    CANtoPDU: function(frame){
        var pdu={};
        pdu.prio = frame.id >>26 & 7
        pdu.edp = !(!(frame.id  >>25 & 1))
        pdu.dp = !(!(frame.id >> 24 & 1))
        pdu.pf = frame.id >> 16 & 255
        pdu.ps = frame.id >> 8 & 255
        pdu.sa = frame.id & 255
        pdu.data = frame.data
        return pdu;
    },
    PDUtoPGN: function(pdu){
        if(pdu.edp && pdu.dp){
            console.log("This is not an ISOBUS Frame, but 15765")
            return null;
        }else{
            //is isobus frame!
            var pgn=0;
            if(pdu.edp)
                pgn|=(1<<17)
            if(pdu.dp)
                pgn|=(1<<16)
            pgn|=(pdu.pf<<8)
            if(pdu.pf>=240)
                pgn|=pdu.ps
            return {pgn:pgn, data:pdu.data};
        }
    },
    PGNtoPDU: function(pgn){
        throw "Not Implemented"
    },
    PDUtoCAN: function(pdu){
        throw "Not Implemented"
    }
}


