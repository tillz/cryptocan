/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
//this decrypter receives two frames and resembles them, as received from encrypter.js in this directory

//our key
var key = new Buffer("3e5595a9e7b764b92985eaff8a448c0e", 'hex')

//Socketcan Wrapper.
var socketcan = require('socketcan');

//OpenSSL Wrapper.
const crypto = require('crypto');

//create Cipher
decipher = crypto.createDecipher("aes-256-ecb", key)
decipher.setAutoPadding(false)

//where encrypted messages are being received.
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

//Create both interfaces
var plainChannel = socketcan.createRawChannel("can1", true);
var cipherChannel = socketcan.createRawChannel("can0", true);
plainChannel.start();
cipherChannel.start();

//stores the last message
var lastmessage=false;

//used to store even/odd message when 'secondid'-Feature is not used
var even_odd = 0;

cipherChannel.addListener("onMessage", function(msg){
    //console.log("Decrypter received 1 message");
    
    var message_resembled=false;
    if(second_id!==false){
        //feature: with second_id
        if(lastmessage===false){
            //we have a clear state
            if(msg.id==encrypted_id){
                //this is a 'first'-frame. Store it!
                lastmessage=msg.data;
            }else if(msg.id==second_id){
                //we have a 'secondary'-message
                //but not yet a 'first'-message.
                //therefore we've started in a running
                //transfer. Ignore this one.
                //console.log("Received 2nd Frame w/o first.")
            }else{
                //received a unknown frame
                //console.log("Received unknown frame")
            }
        }else{
            if(msg.id==second_id){
                //we already have a 'first'-frame:
                //resemble the frame
                message_resembled = Buffer.concat([lastmessage,msg.data])
                //remove the consumed 'first'-message,
                //to allow receiving a fresh frame.
                lastmessage=false;
            }else if(msg.id==second_id){
                //we have received two 'first-frames'.
                //just overwrite the first
                lastmessage=msg.data
                //console.log("Received a 'first'-frame while expecting a 'second'-frame.")
            }else{
                //received a unknown frame
                //console.log("Received unknown frame")
            }
        }
    }else{
        //without feature: Both on one side
        if(msg.id==encrypted_id){
            //only if we have a frame on our encrypted channel!
            if(even_odd%2==0){
                //if even, store
                lastmessage=msg.data;
            }else{
                //if odd, resemble
                message_resembled = Buffer.concat([lastmessage,msg.data])
                lastmessage=false;
            }
            //increase our counter
            even_odd++;
        }else{
            //received a unknown frame
            //console.log("Received unknown frame")
        }
    }
    if(message_resembled!==false){
        //we have a resembled message, decrypt!
        var plaintext = decipher.update(message_resembled);
        
        //extract the id the frame had originally
        var original_id = plaintext.readUInt32BE(0);

        //extract the length the frame had originally
        var original_dlc = plaintext.readUInt8(15);
        
        //it can't be longer than 8 bytes!
        original_dlc = (original_dlc>8 ? 8 : original_dlc);

        //extract whether the original frame had an extended id
        var original_ext = (plaintext.readUInt8(14) == 1);

        //allocate and copy the specified length!
        var original_data = Buffer.alloc(original_dlc);
        plaintext.copy(original_data,0,4,4+original_dlc);
        
        //sent the resembled, decrypted message!
        var original_message = {
                                id:original_id,
                                data:original_data,
                                ext:original_ext
                                };
        //console.log(original_message)
        plainChannel.send(original_message)
        //console.log("Encrypter sent 1 message");
    }
});
//console.log("Listener running, ready to decrypt.")