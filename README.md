# PayShieldPPressureTest
The **pressureTest.py** Python script creates a workload on the Thales appliance payShield 10k and 9k.
They can be useful during demonstrations of the appliance.
They are in an early development stage and still a bit clumsy.
To use them you need to edit the IP of the appliance and the HOST port.
When I will have time, and learn better Python I will create a version that accepts parameters ;-)

# Licensing
Please refer to the **LICENSE** file that is part of this project.
The license is **[AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html)**

# Usage
**pressureTest.py \[-h\] \[--port PORT\] \[--key {2048,4096} | --nc\] \[--forever\] \[--times TIMES\] host**

**host** you need to specify the ip address or the hostname/fqdn of the payShield appliance

**--port** specify the host port. If the parameter is omitted the default value 1500 is used

**--key** the length of the RSA key that the appliance will generate. there are ony two valid values: **2048** or **4096**
if the parameter is not specified **2048** is the default

**--nc** performs just an NC test. It cannot be used in conjunction with **--key**

**--forever** the test will run forever. Use CTRL-c to terminate it

**--times** how many times execute the test. If it is not specified the default value is **1000** times

## Questions bug and suggestions
For any question, feedback, suggestion, send money ***(yes...it's a dream I know)*** you can contact the author at **msz@msz.eu**