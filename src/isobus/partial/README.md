# ISOBUS-specific, PGN-selective encryption.
This folder contains ISOBUS-specific encryption using a supplied configuration file.
For general installation instruction, please see the README.md in the `isobus/` folder.
The configuration needs to be supplied in a file named `keys.json` to both the encrypter and the decrypter.
All JSON-Keys are the PGNs for which encryption should be activated, while the values for this are used as encryption keys.
* `*` is a wildcard which matches all PGNs
* `_*` is a list of PGNs which are excluded from this wildcard
* `x-y` a dash can be used to match ranges of PGNs
* `,` multiple PGNs can be supplied comma-separated
* ranges and commatas can be used together.

## Example Configuration:
```
{
    "*": "760f4491b917e28dc29be7e0ea2fff08", /* Encrypt all PGNs with the key 760f44... */
    "_*": [59136], /* Except PGN 59136 */
    "12345-12350,44,10-20": "860f4491b917e28dc29be7e0ea2fff07", /* Encrypt PGNS 12345, ..., 12350, 10..20, 44 with key 860f44...*/
    "65096": "760f4491b917e28dc29be7e0ea2fff08" /* Encrypt PGN 65096 with key 760f44... */
}
```