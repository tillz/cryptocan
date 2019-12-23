/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
let can = require('socketcan');
let tea = require('../../can/inline/xxtea.js');

var isobus = require('../isobus_common.js');
var keys = require('./keys.json');

//prepare keys
//Part 1: expand comma-separations
for(var k in keys){
    var key = keys[k]
    var cs = k.split(",");
    if(cs.length>1){
        delete keys[k]
        for(var pgn in cs){
            keys[cs[pgn].trim()]=key;
        }
    }
}
//Part 2: expand range expressions
for(var k in keys){
    var key = keys[k]
    var ds = k.split("-");
    if(ds.length>1){
        delete keys[k]
        for(var i=parseInt(ds[0]);i<=parseInt(ds[1]);i++){
            if(i.toString() in keys)
                console.log("WARNING: PGN "+i+" DEFINED TWICE. SELECTED KEY DEPENDS ON ORDER.")
            keys[i.toString()]=key;
        }
    }
}
//Create both interfaces
let plainChannel = can.createRawChannel("can1", true);
let cipherChannel = can.createRawChannel("can0", true);

var cbc = (process.argv.length>2 && process.argv[2]=="cbc")
var lastPacket = Buffer.alloc(8,0)
plainChannel.start();
cipherChannel.start();

function xor(a,b){
    if(a.length!=b.length){
        throw "Length's don't match"
    }else{
        var n=Buffer.alloc(a.length);
        for(var i=0;i<n.length;i++)
            n[i]=a[i]^b[i]
    }
    return n;
}

cipherChannel.addListener("onMessage", function(cipher){
    // Note: A nodejs 'Buffer' has an immutable size
    
    var key=false;
    // check encryption
    var pdu = isobus.CANtoPDU(cipher);
    var pgn = isobus.PDUtoPGN(pdu);
    var iso = pgn.pgn

    //do we have an own key?
    if(keys[iso]){
        key=Buffer.from(keys[iso]);
    }else if(keys['*'] && keys['_*'].indexOf(iso)===-1){
        key=Buffer.from(keys['*']);
    }

    if(key!==false){
        // Allocate 8 Byte buffer filled with zeros
        var b_ciphertext = Buffer.alloc(8,0);
    
        //Copy all bytes in plain.data over
        cipher.data.copy(b_ciphertext);
    
        console.log("Ciphertext: "+b_ciphertext.toString('hex'));
        var b_plaintext = Buffer.from(tea.decrypt(b_ciphertext, key))
        if(cbc){
            b_plaintext=xor(b_plaintext,lastPacket)
        }
        lastPacket=b_ciphertext
        var decrypted_message = {
            id:cipher.id,
            data:b_plaintext,
            ext:cipher.ext
        }
        plainChannel.send(decrypted_message)
        console.log("Cleartext : "+b_plaintext.toString('hex'))
    }else{
        plainChannel.send(cipher)
    }
});
