/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/

//This encrypter receives one frame on a specified ID on can1, and sends the Payload encrypted with xtea over the can0 interface with another specified id
//The padding is simply added, but not communicated to the encrypter, therefore only suitable for specific upper-layer-protocols

let can = require('socketcan');
let tea = require('../xxtea.js');
var key = new Buffer("3e5595a9e7b764b92985eaff8a448c0e", 'hex')


//Create both interfaces
let plainChannel = can.createRawChannel("can1", true);
let cipherChannel = can.createRawChannel("can0", true);
plainChannel.start();
cipherChannel.start();

plainChannel.addListener("onMessage", function(plain){
    // Note: A nodejs 'Buffer' has an immutable size
    
    // Allocate 8 Byte buffer filled with zeros
    var b_plaintext = Buffer.alloc(8,0);
    
    //Copy all bytes in plain.data over
    plain.data.copy(b_plaintext);
    
    console.log("Cleartext : "+b_plaintext.toString('hex'))
    var b_ciphertext = Buffer.from(tea.encrypt(b_plaintext, key))
    var encrypted_message = {
        id:plain.id,
        data:b_ciphertext,
        ext:plain.ext
    }
    cipherChannel.send(encrypted_message)
    console.log("Ciphertext: "+b_ciphertext.toString('hex'));
});
