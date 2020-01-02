# ISOBUS-specific CAN encryption.
To be able to interpret the received ISOBUS messages, the database of PGNs and SPNs is required.
Due to copyright reasons, please download this on your own from the [ISOBUS site](https://www.isobus.net/isobus/) (ISOBUS Parameters: Complete list with details – CSV) and place the contained `SPNs and PGNs.csv`-file in this folder.
To run, please install [nodejs](https://nodejs.org/en/), for example from [nodesource](https://github.com/nodesource/distributions/blob/master/README.md):
```
curl -sL https://deb.nodesource.com/setup_12.x | bash -
apt-get install -y nodejs
```
Additionally, a SocketCAN-Wrapper for NodeJS is required, which can be installed using `npm i socketcan`.
Afterwards, execute the program with nodejs, e.G. `node isobus.js`