const { exec } = require('child_process');
const xml2js = require('xml2js');
// nmap -T5 -sV -O -oX - --open -p
//nmap -T4 -A -O --osscan-limit --osscan-guess -oX 
//nmap -T4 -A -O -oX 
//--max-os-tries
// function runNmapWorker(target, callback) {
//   exec(`nmap -T4 -A --max-os-tries -oX  - ${target}`, (err, stdout, stderr) => {
//     if (err) {
//       callback(err);
//     } else {
//       const results = parseNmapXml(stdout, target);
//       callback(null, results);
//     }
//   });
// } 6000
function runNmapWorker(target, callback) {
    exec(`nmap -T5 -sT -O --max-os-tries 3 -oX - ${target}`, (err, stdout, stderr) => {
      if (err) {
        callback(err);
      } else {
        const results = parseNmapXml(stdout, target);
        callback(null, results);
      }
    });
  }

function parseNmapXml(xml, target) {
  let results = {};
  xml2js.parseString(xml, (err, result) => {
    if (err) {
      console.error(`Error parsing Nmap XML output: ${err}`);
      return;
    }
    // extract relevant data from the XML object
    // console.log(JSON.stringify(result, null, 2));
    console.log(target);
    var hostname = "";
    var addresses = [];
    var ports = [];
    var os = [];
    if (result.nmaprun.runstats[0].hosts[0].$.up == 1) {
      if (Object.keys(result.nmaprun).includes('host')) {
        const host = result.nmaprun.host[0];
        hostname = getHostname(host.hostnames[0], target);
        addresses = host.address;
        ports = host.ports[0].port;
        os = getOS(host.os[0].osmatch);
      }
    }

    // create an object to store the results
    results = {
      hostname,
      addresses: addresses.map(addr => addr.$.addr),
      openPorts: ports.filter(port => port.state[0].$.state === 'open').map(port => ({
        port: port.$.portid,
        protocol: port.$.protocol,
        service: port.service[0].$.name,
        product: port.service[0].$.product,
        version: port.service[0].$.version ? port.service[0].$.version : null,
        cpe: port.service[0].cpe ? port.service[0].cpe[0].replace('/a', '2.3:a').replace('/o', '2.3:o') : null
      })),
      os,
      hostStatus: result.nmaprun.runstats[0].hosts[0].$
    };
  });
  return results;
}

function getOS(os) {
  var osName = "";
  var osConfidence = "";
  var osCPE = "";
  if(os && os.length > 0) {
    var matchOS = os[0];
    osName = matchOS.$.name;
    osConfidence = matchOS.$.accuracy;
    try {
      osCPE = matchOS.osclass[0].cpe[0].replace('/a', '2.3:a').replace('/o', '2.3:o');
    } catch {
      osCPE = "";
    }
  }

  return {
    osName,
    osConfidence,
    osCPE
  }
}

function getHostname(data, fallback) {
  var hostname = [];
  if(typeof(data) === 'object') {
    data.hostname.forEach(element => {
      hostname.push(element.$.name);
    });
  } else {
    hostname.push(fallback);
  }
  return hostname;
}

module.exports = {
  runNmapWorker,
};
