/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/

//this receives one packet, and sends the ID and Payload encrypted with aes-256-ecb as two frames
//on a specified ID.
//Two sent frames are only identified using their order.
//No Handling for standard/extended-frames exists so far

//our key
var key = new Buffer("3e5595a9e7b764b92985eaff8a448c0e", 'hex')

//Socketcan Wrapper.
var socketcan = require('socketcan');

//OpenSSL Wrapper.
const crypto = require('crypto');

//create Cipher
cipher = crypto.createCipher("aes-256-ecb", key)
cipher.setAutoPadding(false)

//where encrypted messages are being sent.
var encrypted_id = 1

/* Feature:
Frames can be sent in two ways. Either with the same id,
or with two ids for the first resp. second frame.
If two IDs can be used, the transport will be significantly more stable,
as it's clear whether the frame is the first or the second part of
a original frame.
If this is set to false, both are sent on the same id.
Please note that the receiver needs to have the same setting!
*/
var second_id = 2;

//whether the encrypted message are being sent in extended frames.
var encrypted_ext = true;

//Create both interfaces
var plainChannel = socketcan.createRawChannel("can1", true);
var cipherChannel = socketcan.createRawChannel("can0", true);
plainChannel.start();
cipherChannel.start();


var only_id = 12342
var inc_id = false;

plainChannel.addListener("onMessage", function(msg){
    frame_recv = BigInt(msg.ts_sec*1000000000+msg.ts_usec*1000)
    if(only_id!==false && msg.id!=only_id){
        return
    }
    if(inc_id){
        msg.id++;
    }

    //allocate a buffer for two frames
    var fullmessage = Buffer.alloc(16)

    //copy over the id, starting at byte 0
    fullmessage.writeUInt32BE(msg.id);

    //copy over the length, starting at byte15
    fullmessage.writeUInt8(msg.data.length,15);

    //copy over the payload, starting at 4 (could start
    //earlier if we'd had only standard-frames, but the space is free
    //anyways)
    msg.data.copy(fullmessage,4,0,msg.data.length);

    //copy over whether the incoming frame was an extended frame
    fullmessage[14] = msg.ext ? 1 : 0;
    
    //now we have the full message assembled
    //console.log(fullmessage)

    //encrypt it!
    var ciphertext = cipher.update(fullmessage);
    //console.log(ciphertext)

    //and split into two.
    var msg1_data = Buffer.alloc(8);
    var msg2_data = Buffer.alloc(8);
    ciphertext.copy(msg1_data, 0, 0, 8)
    ciphertext.copy(msg2_data, 0, 8, 16)
    var msg1={id:encrypted_id, ext:encrypted_ext, data:msg1_data}
    var msg2={id:(second_id===false ? encrypted_id : second_id), ext:encrypted_ext, data:msg2_data};
    cipherChannel.send(msg1);
    cipherChannel.send(msg2);
    frame_sent = BigInt(msg1.ts_sec*1000000000+msg1.ts_usec*1000)

});


// Ciphertext Layout:
// |ID3|ID2|ID1|ID0|DATA7|DATA6|DATA5|DATA4|DATA3|DATA2|DATA1|DATA0|0|0|EID|DLC