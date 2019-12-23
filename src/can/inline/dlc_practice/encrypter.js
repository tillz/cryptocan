/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
//This encrypter receives one frame on a specified ID on can0, and sends the Payload encrypted with xtea over the vcan0 interface with another specified id
//The padding length is encoded in the addditional DLC bits, if the driver supports it.

//our key (256 bit)
var key = new Buffer("3e5595a9e7b764b92985eaff8a448c0e", 'hex')

//Socketcan Wrapper.
var socketcan = require('socketcan');

//Encryption
const tea = require('../xxtea.js');

//where encrypted messages are being sent.
var encrypted_id = 12342;
var decrypted_id = 12342;

//Create both interfaces
var plainChannel = socketcan.createRawChannel("can0", true);
var cipherChannel = socketcan.createRawChannel("vcan0", true);
plainChannel.start();
cipherChannel.start();

plainChannel.addListener("onMessage", function(msg){
    if(msg.id!=decrypted_id)
        return
    console.log("Encrypter received 1 message");

    var padded_data = Buffer.alloc(8);
    msg.data.copy(padded_data);
    if(msg.data.length!=0)
        var ciphertext = Buffer.from(tea.encrypt(padded_data, key))
    else
        var ciphertext = Buffer.alloc(0)
    
    //sent the resembled, decrypted message!
    var encrypted_message = {
                            id:encrypted_id,
                            data:ciphertext,
                            ext:true,
                            res0:(msg.data.length==0) ? 0 : (8-msg.data.length)
                            };
    console.log(encrypted_message)
    cipherChannel.send(encrypted_message)
    console.log("Encrypter sent 1 message");
});
console.log("Listener running, ready to encrypt.")
