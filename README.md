# PayShieldPPressureTest
The **pressureTest.py** Python script creates a workload on the **Thales** appliance **payShield** **10k** and **9k**.

The script can be useful during demonstrations of the appliance.

The project is in an early development stage and still a bit clumsy.


## Usage
**pressureTest.py \[-h\] \[--port PORT\] \[--key {2048,4096} | --nc\] \[--forever\] \[--times TIMES\] host**

**host** you need to specify the ip address or the hostname/fqdn of the **payShield** appliance

**--port** specify the host port. If the parameter is omitted the default value **1500** is used

**--key** the length of the RSA key that the appliance will generate. there are ony two valid values: **2048** or **4096**
if the parameter is not specified **2048** is the default

**--nc** performs just an NC test. It cannot be used in conjunction with **--key**

**--forever** the test will run forever. Use CTRL-c to terminate it

**--times** how many times execute the test. If it is not specified the default value is **1000** times

## COPYRIGHT & LICENSE
  Please refer to the **LICENSE** file that is part of this project.
  The license is **[AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html)**
  
  Copyright(C) 2020  **Marco S. Zuppone** - **msz@msz.eu** - [](https://msz.eu)

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as
  published by the Free Software Foundation, either version 3 of the
  License, or any later version.

  This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
   GNU Affero General Public License for more details.
   
## Questions bug and suggestions
For any question, feedback, suggestion, send money ***(yes...it's a dream I know)*** you can contact the author at **msz@msz.eu**
