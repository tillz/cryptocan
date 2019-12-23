/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/
/*
Parse and replay a recorded ISOBUS/CANDUMP with the syntax:
(1.752600) can0 1CAAF880#0003FFFFFFFFFFFF
The Frames are always sent on CAN0, regardless of the can interface they were received on.

*/
var can = require('socketcan');
var channel = can.createRawChannel("can0", true);

channel.start();

var messages={};
var lines = require('fs').readFileSync(process.argv[2], 'utf-8')
    .split('\n')
    .filter(Boolean);
    
for(var k in lines){
    var line=lines[k]
    var re=/\(([^\)]+)\) can0 ([^#]+)#(.*)/
    var matches=line.match(re)
    messages[parseInt(parseFloat(matches[1])*1000)]={id:parseInt(matches[2],16), data:Buffer.from(matches[3], 'hex'), ext:true}
}
var start=new Date().getTime()
var first=false
console.log("starting at "+start)
for(var k in messages){
    if(first===false){
        first=k;
    }
    var t=new Date().getTime()
    while((t-start)<(k-first)){
        t=new Date().getTime()
    }
    console.log("sending message: ")
    console.log(messages[k])
    channel.send(messages[k])
}