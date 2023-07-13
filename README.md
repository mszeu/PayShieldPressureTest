# PayShieldPPressureTest

<img src=images/supporting-member-badge.png width=100>

The **pressureTest.py** Python script creates a workload on the **Thales payShield 10k** and **9k** appliances.  
The script can be useful during demonstrations of the monitoring features of the appliance and can be used in every case
you need to generate a workload for testing purposes.

It requires **Python 3**. It was tested on **Python 3.10.2*** using a **payShield 10k** with firmware **1.7**.

## Version

**1.3**

## Usage

    pressureTest.py [-h] [--port PORT]
                  [--key KEY | --nc | --no | --ni | --pci | --j2 | --j4 | --j8 | --jk | --b2 | --randgen | --ecc]
                  [--ecc-curve {0,1,2}] [--key-use {S,X,N}] [--key-exportability {N,E,S}] [--header HEADER]
                  [--forever] [--decode] [--times TIMES] [--proto {tcp,udp,tls}] [--keyfile KEYFILE] 
                  [--crtfile CRTFILE] [--echo ECHO]
                  host

### Mandatory parameter(s)

**host** *ip address* or the *hostname/fqdn* of the **payShield** appliance.

### Mutually exclusive parameters

**--key** the length in bits of the RSA keys to generate. The value needs to be between **320** and **4096**.

**--nc** performs just an **NC** test. 

**--pci** gathers the PCI compliance status of the payShield through the **NO** command, type **01**. 

**--no** gathers the status of the payShield through the **NO** command, type **00**. 

**--ni** gathers the Ethernet Host Port 1 status through the **NI** command. 

**--j2** gets HSM Loading using **J2** command. 

**--j4** gets Host Command Volumes using **J4** command. 

**--j8** gets Health Check Accumulated Counts using **J8** command. 

**--jk** gets Instantaneous Health Check Status using **JK** command. 

**--randgen** Generates a random value 8 bytes long using **N0** command.

**--b2** Echoes received data, specified through the **--echo** parameter, back to the user.

**--ecc** Generates an ECC public/private key pair using the Elliptic Curve algorithm.  
By default, the curve used is NIST P-521, the exportability is 'S' (Sensitive)
and the key usage is 'S' (Only digital signature).  
Use the parameters **--ecc-curve**, **--key-use** and **--key-exportability** to change the default values. 

### Optional parameters

**--port** specifies the host port, if omitted the default value **1500** is used.

**--proto** specifies the protocol to use, **tcp**, **udp** or **tls**, if omitted the default value **tcp**
is used.  
If **tls** is used you might specify the path of the client key file and the certificate using the parameters
**--keyfile** and **--crtfile**.   
No verifications are performed about the validity of certificates.

**--keyfile** the path of the client key file, if is not specified the default value is **client.key**.  
It's only considered if the protocol is **tls**.

**--crtfile** the path of the client certificate file, if is not specified the default value is **client.crt**.  
It's only considered if the protocol is **tls**.

**--header** the header string to prefix to the host command, if not specified the default value is **HEAD**.

**--echo** specifies the payload sent using the echo command **--b2**, otherwise it is ignored

**--forever** the test will run forever. Use **CTRL-C** to terminate it.

**--times** how many times execute the test. If it is not specified, the default value is **1000** times.

**--decode** decodes the response of the payShield if a decoder function is available for the command.  
The commands **--decode** supports in the release are: **B2**, **N0**, **NO**, **NC**, **J2**, **J4**, **J8**, **JK** and **FY (ECC)**.

**--ecc-curve** sets the ECC curve to use when **--ecc** is used. The default is NIST P-521.  
The possible choices are:
 - 0: FIPS 186-3 – NIST P-256
 - 1: FIPS 186-3 – NIST P-384
 - 2: FIPS 186-3 – NIST P-521

**--key-use** sets the key usage. The default one is **'S'** (Signature only).   
The possible choices are:
 - S: The key may only be used to perform digital signature generation operations. 
 - X: The key may only be used to derive other keys. 
 - N: No special restrictions apply.

**--key-exportability** sets the key exportability. The default is **'S'** (Sensitive).  
The possible choices are:
 - E: May only be exported in a trusted key block, provided the wrapping key itself is in a trusted format.
 - N: No export permitted.
 - S: Sensitive; all other export possibilities are permitted, provided such export has been enabled (existing Authorized State requirements remain).
 
## Example

    C:\Test>python pressureTest.py 192.168.0.36 --nc --times 2

    PayShield stress utility, version 1.3, by Marco S. Zuppone - msz@msz.eu - https://msz.eu
    To get more info about the usage invoke it with the -h option This software is open source, and it is under the Affero
    AGPL 3.0 license

    Iteration:  1 of 2

    Return code: 00 No error
    Command sent/received: NC ==> ND
    sent data (ASCII) : b'HEADNC'
    sent data (HEX) : b'0006484541444e43'
    received data (ASCII): b'HEADND005D672700000000001500-0023'
    received data (HEX) : b'0021484541444e44303035443637323730303030303030303030313530302d30303233'
    
    Iteration:  2  of  2
    
    Return code: 00 No error
    Command sent/received: NC ==> ND
    sent data (ASCII) : b'HEADNC'
    sent data (HEX) : b'0006484541444e43'
    received data (ASCII): b'HEADND005D672700000000001500-0023'
    received data (HEX) : b'0021484541444e44303035443637323730303030303030303030313530302d30303233'
    
    DONE

## NOTES

The **EI** command used to generate the RSA key requires authorization, and the generation of 4096-bit keys is possible only for keyblock LMKs.

The **--ecc** parameter uses the **FY** command to generate ECC keypairs: 
The functionality may require a license and/or a firmware update, depending on the firmware version.

## COPYRIGHT & LICENSE
  Please refer to the **LICENSE** file that is part of this project.
  The license is **[AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html)**
  
  Copyright(C) 2020-2023  **Marco S. Zuppone** - **msz@msz.eu** - [https://msz.eu](https://msz.eu)

This program is free software: you can redistribute it and/or modify  
it under the terms of the GNU Affero General Public License as  
published by the Free Software Foundation, either version 3 of the  
License, or any later version.

This program is distributed in the hope that it will be useful,  
but **WITHOUT ANY WARRANTY; without even the implied warranty of  
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.** See the  
**GNU Affero General Public License** for more details.

## Questions, bugs & suggestions
For any questions, feedback, suggestions, send money ***(yes...it's a dream, I know)*** you can contact the author at [msz@msz.eu](mailto:msz@msz.eu)
