# PayShieldPPressureTest
The **pressureTest.py** Python script creates a workload on the **Thales payShield 10k** and **9k** appliances.

The script can be useful during demonstrations of the monitoring features of the appliance and can be used in every case you need to generate a workload for testing purposes.
 
The project is in an early development stage and still a bit clumsy.

It requires **Python 3**. It was tested on **Python 3.7** and **3.8** using a **payShield 10k**.


## Usage

**pressureTest.py \[-h\] \[--port PORT\] \[--proto {tcp, udp}\] \[--key {2048,4096} | --nc | --j2 | --j4 | --n8 | --jk | --randgen\] \[--head HEADER\] \[--forever\] \[--times TIMES\] host**

**host** you need to specify the ip address or the hostname/fqdn of the **payShield** appliance.

**--port** specify the host port. If the parameter is omitted the default value **1500** is used.

**--proto** specify the protocol to use, **tcp** or **udp**. If the parameter is omitted the default value **tcp** is used.

**--key** the length of the RSA key that the appliance will generate. there are ony two valid values: **2048** or **4096**.
if the parameter is not specified **2048** is the default.

**--header** the header string to prefix to the host command. if is not specified the default value is **HEAD**.

**--nc** performs just an **NC** test. It cannot be used in conjunction with **--key**.

**--j2** get HSM Loading using **J2** command. It cannot be used in conjunction with **--key**.

**--j4** get Host Command Volumes using **J4** command. It cannot be used in conjunction with **--key**.

**--j8** get Health Check Accumulated Counts using **J8** command. It cannot be used in conjunction with **--key**.

**--jk** get Instantaneous Health Check Status using **JK** command. It cannot be used in conjunction with **--key**.

**--randgen** Generate a random value 8 bytes long using **N0** command. It cannot be used in conjunction with **--key**.

**--forever** the test will run forever. Use **CTRL-C** to terminate it.

**--times** how many times execute the test. If it is not specified the default value is **1000** times.

## Example
C:\Test>*python pressureTest.py 192.168.0.36 --nc --times 2*

PayShield stress utility by Marco S. Zuppone - msz@msz.eu  
To get more info about the usage invoke it with the -h option  
This software is open source and it is under the Affero AGPL 3.0  


Return code: 0 OK  
Command sent/received: NC ==> ND  
sent data (ASCII) : b'HEADNC'  
sent data (HEX) : b'0006484541444e43'  
received data (ASCII): b'HEADND00451BC800000000001500-0023'  
received data (HEX) : b'0021484541444e44303034353142433830303030303030303030313530302d30303233'  
Iteration:  1  


Return code: 0 OK  
Command sent/received: NC ==> ND  
sent data (ASCII) : b'HEADNC'  
sent data (HEX) : b'0006484541444e43'  
received data (ASCII): b'HEADND00451BC800000000001500-0023'  
received data (HEX) : b'0021484541444e44303034353142433830303030303030303030313530302d30303233'  
Iteration:  2  

## NOTES

The **EI** command used to generate the RSA key requires authorization and the generation of 4096 bit keys is possible only for keyblock LMKs.


## COPYRIGHT & LICENSE
  Please refer to the **LICENSE** file that is part of this project.
  The license is **[AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html)**
  
  Copyright(C) 2020  **Marco S. Zuppone** - **msz@msz.eu** - [](https://msz.eu)

  This program is free software: you can redistribute it and/or modify  
  it under the terms of the GNU Affero General Public License as  
  published by the Free Software Foundation, either version 3 of the  
  License, or any later version.  

  This program is distributed in the hope that it will be useful,  
   but ***WITHOUT ANY WARRANTY; without even the implied warranty of  
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.** See the  
   GNU Affero General Public License for more details.  
   
## Questions, bugs & suggestions
For any questions, feedback, suggestions, send money ***(yes...it's a dream I know)*** you can contact the author at **msz@msz.eu**
