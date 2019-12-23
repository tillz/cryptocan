/*
Cryptocan - a minimalistic, backward-compatible, and failure resistant CAN-bus encryption
Copyright (C) 2019 Till Zimmermann

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
*/

/* 
This program interprets isobus frames according to the PGN/SPN database, outputs them and logs them if requested.
See `node isobus.js` to see help
*/
var can = require('socketcan');
const csv = require('csv-parser')
const fs = require('fs')
var timestamp = require('monotonic-timestamp')
var isobus = require('./isobus_common.js');

var logging = {};
var nargv = process.argv.slice(3)
console.log(process.argv[2])
var channel = can.createRawChannel(process.argv[2], true);
if(nargv.length<2){
    console.log("usage: node isobus.js can_interface [pgn_spn_logfile...]");
    console.log("pgn_spn_logfile can be used to extract single SPNs and save them to a logfile.");
    console.log("The format for each pgn_spn_logfile argument is as follows: spnToBeLogged_FileNameForLog_FactorToBeApplied,");
    console.log("e.g.where FactorToBeApplied is applied to the SPN before writing and can be skipped to get the unscaled value.");
    console.log("The unit and factor are part of the `SPNs and PGNs.csv` database, and need to be interpreted by humans");
    process.exit(1)
}
for(var k in nargv){
    var arg = nargv[k].split('_')
    logging[arg[0]] = {spn:arg[1],file:fs.createWriteStream(arg[2]), factor: parseFloat(arg[3]||1)}
}

var pgns={}
var all={}
fs.createReadStream("SPNs and PGNs.csv")
  .pipe(csv())
  .on('data', function(a) {
    var pgn=parseInt(a['pgn'])
    var spn=parseInt(a['spn'])
    all[pgn] = all[pgn]||{};
    all[pgn][spn]=a;
    //old:
    pgns[parseInt(a['pgn'])]=a.parameter_group_label

  })
  .on('end', function() {
    console.log("Finished reading PGNs, starting channel");
    channel.start();
  });
function parsePGN(pgn_u, buffer){
    var dat={}
    for(var spn in all[pgn_u]){
        var spn_o = all[pgn_u][spn]
        var start;
        var val1=0;
        var val2=0;
        var val;
        if(spn_o['spn_length'].length==0)
            continue
        var spn_l=spn_o['spn_length']
        if(spn_l.indexOf(' ')!=-1){
            spn_l = spn_l.split(' ')[0]
        }
        if(spn_o['spn_position_in_pgn'].indexOf('.')!=-1){  //this is a bit
            var bits = spn_o['spn_position_in_pgn'].split('.');
            start = (bits[0]-1)*8+(bits[1]-1)
        }else{
            var bits = spn_o['spn_position_in_pgn'].split('-');
            start = (bits[0]-1)*8;
        }
        if(spn_l<=8){
            val1=buffer.readUInt8(parseInt(start/8));
            if(start<56)//otherwise, end of packet
                val2=buffer.readUInt8(parseInt(start/8)+1)>>8;
        }else if(spn_l<=16){
            val1=buffer.readUInt16LE(parseInt(start/8));
            if(start<48)//otherwise, end of packet
                val2=buffer.readUInt8(parseInt(start/8)+2)>>16;
        }else if(spn_l<=32){
            val1=buffer.readUInt32LE(parseInt(start/8));
            if(start<32)//otherwise, end of packet
                val2=buffer.readUInt8(parseInt(start/8)+4)>>32;
        }else{
            console.log("Unexpected length:");
            console.log(spn_o)
        }
        if(start%8!=0){
            val = (val1|val2)<<(start%8)
        }else{
            val=val1;
        }
        if(spn_l<8) {
            var bitmask=1;
            for(var i=1;i<spn_l;i++){
                bitmask|=1<<(i-1);
            }
            val&=bitmask;
        }
        dat[spn]=val;
    }
    return dat
}
  



var uniqpgns={}
channel.addListener("onMessage", function(msg){
    var pdu = isobus.CANtoPDU(msg);
    var pgn = isobus.PDUtoPGN(pdu);
    var iso = pgn
    uniqpgns[iso.pgn]= uniqpgns[iso.pgn]+1 || 1;
    
    if(logging[iso.pgn]){
        var logg = logging[iso.pgn];
        var f=parsePGN(iso.pgn,msg.data)
        var t='';
        if(logg.spn=='*'){
        
            //special case for VT communication, used to extract
            //sprayer tank. Not part of any standard and different from setup to setup.
            //Only left here fore reference (will never be executed!)
            if(iso.pgn==59136 && false){
                if(msg.data.readUInt16LE(1)==318 && msg.data.readUInt8(0)==0xA8){
                    t=msg.data.readUInt16LE(4);
                }else{
                    return
                }
            }else{
                for(var k in f){
                    t+=f[k]+"\t"
                }
            }
        }else{
            t=f[logg.spn]*logg.factor;
        }
        logg.file.write(timestamp()+"\t"+t+"\n")
    }

    // Here, the parsing of different PGNs can be added. Some examples are as follows:

    // 129025: Position Rapid Update
    if(iso.pgn==129025){
        var g={lat:msg.data.readInt32LE(0)*0.0000001,lon:msg.data.readInt32LE(4)*0.0000001}
        console.log(g)
    }
    
    //wheel based speed
    if(iso.pgn==65096 ){
        var speed=msg.data.readUInt16LE(0)*0.001 //m/s
        speed=speed*3600 ///m/h
        speed=speed/1000 ///km/h
        console.log(iso.pgn+'_'+speed)
    }
    
    //ground based speed
    if(iso.pgn==65097){
        var speed1=msg.data.readUInt8(0)*0.001 //m/s
        var speed2=msg.data.readUInt8(1)*0.001 //m/s
        var speed=speed1+(speed2<<8);
        speed=speed*3600 ///m/h
        speed=speed/1000 ///km/h
        console.log(iso.pgn+'_'+speed)
    }
    
    //Primary or Rear Power Take off Output Shaft
    if(iso.pgn==65091 ){
        var speed=msg.data.readUInt16LE(0)*0.125 //m/s
        console.log(iso.pgn+'_'+speed)
    }
});

function cb(i){
    return function(){
        console.log("Closed"+i)
        logging[i]=false;
    }
}


process.on('SIGINT', function() {
    console.log("Caught interrupt signal");
    var wait=false;
    for(var k in logging){
        if(logging[k]!==false){
            logging[k].file.end(cb(k))
            wait=true
        }
        if(!wait)
            process.exit(0)
    }
    setTimeout(function() {
        var wait=false;
        for(var k in logging){
            if(logging[k]!==false){
                wait=true
            }
        }
        if(!wait)
            process.exit(0)
    },1000)
});









































/*
Row {
  'pgn': '8960',
  parameter_group_label: 'Tractor Implement Management (TIM) Server to TIM Client',
  acronym: 'TIM12',
  pgn_description:
   'Tractor Implement Management (TIM) Server to TIM Client Status, Operation and Function messages. The first byte of the PGN contains the Message code or the TIM function ID.',
  edp: '0',
  dp: '0',
  pf: '35',
  ps: 'DA',
  multipacket: 'Yes',
  transmission_rate: 'As Required',
  pgn_data_length: 'Variable',
  default_priority: '7',
  pgn_reference: '',
  spn_position_in_pgn: '3.1',
  spn: '8708',
  spn_name: 'Auxiliary Valve 11 Automation Status',
  spn_description:
   'This parameter is used to report the Auxiliary valve 11 automation status',
  spn_length: '4',
  resolution: '16 states/4 bit',
  offset: '0',
  data_range: '0 to 15',
  operational_range: '',
  units: 'Bit Field',
  slot_identifier: '89',
  slot_name: 'SAEbs04',
  spn_type: 'Status',
  spn_reference: '',
  spn_document: 'ISO 11783',
  pgn_document: 'ISO 11783',
  spn_created_or_modified_date: '2017-02-21',
  pgn_created_or_modified_date: '',
  pgn_spn_mapping_created_or_modified_date: '2017-02-21' }
  */