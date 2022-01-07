[comment]: # "Auto-generated SOAR connector documentation"
# CheckPhish

Publisher: Splunk Community  
Connector Version: 1\.0\.1  
Product Vendor: Bolster  
Product Name: Checkphish  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app provides investigative actions for bolster\.ai and checkphish\.ai

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2021 Splunk Inc."
[comment]: # "  Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "  you may not use this file except in compliance with the License."
[comment]: # "  You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "      http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # "  Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "  the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "  either express or implied. See the License for the specific language governing permissions"
[comment]: # "  and limitations under the License."
[comment]: # ""
Please note that running the test connectivity action on this app will submit a URL for detonation
potentially counting against API key quota.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Checkphish asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_url** |  required  | string | API URL for Scan Requests
**api\_key** |  required  | password | API Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[check status](#action-check-status) - Get URL scan Results  
[detonate url](#action-detonate-url) - Submit a URL for scan  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'check status'
Get URL scan Results

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**job\_id** |  required  | Job ID retrieved during a previous URL scan | string |  `checkphish job id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.job\_id | string |  `checkphish job id` 
action\_result\.data\.\*\.brand | string | 
action\_result\.data\.\*\.disposition | string | 
action\_result\.data\.\*\.error | boolean | 
action\_result\.data\.\*\.insights | string | 
action\_result\.data\.\*\.job\_id | string |  `checkphish job id` 
action\_result\.data\.\*\.resolved | boolean | 
action\_result\.data\.\*\.screenshot\_path | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.data\.\*\.url\_sha256 | string |  `url`  `sha256` 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'detonate url'
Submit a URL for scan

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**url** |  required  | URL to be scanned | string |  `url` 
**scan\_type** |  required  | Type of scan to run | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.scan\_type | string | 
action\_result\.parameter\.url | string |  `url` 
action\_result\.data\.\*\.jobID | string |  `checkphish job id` 
action\_result\.data\.\*\.timestamp | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.summary\.job\_id | string |  `checkphish job id` 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 