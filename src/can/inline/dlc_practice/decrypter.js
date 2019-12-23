/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
// Counterpart for encrypter.js in this directory


//our key (128 bit)
var key = new Buffer("3e5595a9e7b764b92985eaff8a448c0e", 'hex')

//Socketcan Wrapper.
var socketcan = require('socketcan');

//Encryption
const tea = require('../xxtea.js');

//where encrypted messages are being received.
var encrypted_id = 12342;
var decrypted_id = 12343;


//Create both interfaces
var plainChannel = socketcan.createRawChannel("can0", true);
var cipherChannel = socketcan.createRawChannel("vcan0", true);
plainChannel.start();
cipherChannel.start();

cipherChannel.addListener("onMessage", function(msg){
    console.log(msg)
    if(msg.id!=encrypted_id)
        return
    console.log("Decrypter received 1 message");

    var original_data;
    if(msg.data.length!=0){
        var plaintext = Buffer.from(tea.decrypt(msg.data, key))
    
        //it can't be longer than 8 bytes!
        original_dlc = 8-msg.res0;

        //allocate and copy the specified length!
        original_data = Buffer.alloc(original_dlc);
        plaintext.copy(original_data,0,0,original_dlc);
    }else{
        original_data = Buffer.alloc(0);
    }
    //sent the resembled, decrypted message!
    var original_message = {
                            id:decrypted_id,
                            data:original_data,
                            ext:true
                            };
    console.log(original_message)
    plainChannel.send(original_message)
    console.log("Decrypter sent 1 message");
});
console.log("Listener running, ready to decrypt.")