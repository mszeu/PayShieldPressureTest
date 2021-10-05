# PayShieldPPressureTest

<a href="https://www.jetbrains.com/?from=PayshieldPPressureTest"><img src=images/jetbrains-variant-3.png width=100></a>
Many thanks to <a href="https://www.jetbrains.com/?from=PayshieldPPressureTest">JetBrains</a> for giving us the <b>Open
Source License</b> for free with the full access to their developer suite.
<a href="https://www.jetbrains.com/pycharm/?from=PayshieldPPressureTesPyCharm">PyCharm</a> is an awesome Python IDE that
greatly simplified my work.

&nbsp;

The **pressureTest.py** Python script creates a workload on the **Thales payShield 10k** and **9k** appliances.  
The script can be useful during demonstrations of the monitoring features of the appliance and can be used in every case
you need to generate a workload for testing purposes.

The project is in an early development stage and still a bit clumsy.

It requires **Python 3**. It was tested on **Python 3.7** and **3.8** using a **payShield 10k** with firmware **1.3a**

## Version

**1.1.4a**

## Usage

    pressureTest.py [-h] [--port PORT] [--key {2048,4096} | --nc | --no | --pci | --j2 | --j4 | --j8 | --jk | --randgen | --b2]
                    [--header HEADER] [--times TIMES] [--forever] [--decode] [--proto {tcp,udp,tls}] 
                    [--keyfile KEYFILE] [--crtfile CRTFILE] [--echo]
                    host

### Mandatory parameter(s)

**host** *ip address* or the *hostname/fqdn* of the **payShield** appliance.

### Mutually exclusive parameters

**--key** the length of the RSA to generate. There are only two valid values: **2048** or **4096**.  
If not specified, **2048** is the default.

**--nc** performs just an **NC** test. 

**--pci** gathers the PCI compliance status of the payShield through the **NO** command, type **01**. 

**--no** gathers the status of the payShield through the **NO** command. 

**--j2** get HSM Loading using **J2** command. 

**--j4** get Host Command Volumes using **J4** command. 

**--j8** get Health Check Accumulated Counts using **J8** command. 

**--jk** get Instantaneous Health Check Status using **JK** command. 

**--randgen** Generate a random value 8 bytes long using **N0** command.

**--b2** Echo received data, specified through the **--echo** parameter, back to the user.

### Optional parameters

**--port** specifies the host port, if omitted the default value **1500** is used.

**--proto** specify the protocol to use, **tcp**, **udp** or **tls**, if omitted the default value **tcp**
is used.  
If **tls** is used you might specify the path of the client key file and the certificate using the parameters **
--keyfile** and **--crtfile**.

**--keyfile** the path of the client key file, if is not specified the default value is **client.key**.  
It's only considered if the protocol is **tls**.

**--crtfile** the path of the client certificate file, if is not specified the default value is **client.crt**.  
It's only considered if the protocol is **tls**.

**--header** the header string to prefix to the host command, if not specified the default value is **HEAD**.

**--echo** specify the payload sent using the echo command **--b2**, otherwise it is ignored

**--forever** the test will run forever. Use **CTRL-C** to terminate it.

**--times** how many times execute the test. If it is not specified the default value is **1000** times.

**--decode** decodes the response of the payShield if a decoder function is available for the command.  
The commands **--decode** supports in the release are: **B2**, **N0**, **NO**, **NC**, **J2**, **J4**, **J8** and **JK**.

## Example

    C:\Test>python pressureTest.py 192.168.0.36 --nc --times 2

    PayShield stress utility, version 1.1.3, by Marco S. Zuppone - msz@msz.eu - https://msz.eu
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


## COPYRIGHT & LICENSE
  Please refer to the **LICENSE** file that is part of this project.
  The license is **[AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html)**
  
  Copyright(C) 2020-2021  **Marco S. Zuppone** - **msz@msz.eu** - [https://msz.eu](https://msz.eu)

This program is free software: you can redistribute it and/or modify  
it under the terms of the GNU Affero General Public License as  
published by the Free Software Foundation, either version 3 of the  
License, or any later version.

This program is distributed in the hope that it will be useful,  
but **WITHOUT ANY WARRANTY; without even the implied warranty of  
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.** See the  
**GNU Affero General Public License** for more details.

## Questions, bugs & suggestions
For any questions, feedback, suggestions, send money ***(yes...it's a dream I know)*** you can contact the author at **msz@msz.eu**
