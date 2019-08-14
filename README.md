# PyBeef
BeEF is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser.<br/><br/>
[+]  Amid growing concerns about web-borne attacks against clients, including mobile clients, BeEF allows the professional penetration tester to assess the actual security posture of a target environment by using client-side attack vectors.<br/><br/>[+] Unlike other security frameworks, BeEF looks past the hardened network perimeter and client system, and examines exploitability within the context of the one open door: the web browser.<br/><br/>[+] BeEF will hook one or more web browsers and use them as beachheads for launching directed command modules and further attacks against the system from within the browser context.<br/><br/>
**PyBeef** is an Interaction to Beef using REST API provided by the BEEF Framework

### Required Packages
1. requests<br/>
2. tabulate<br/>
3. reportlab<br/>

### How to Use PyBeef
**Features**<br/>
1. Execute Command Modules Automatically.<br/>
2. Generate PDF Report for the Hooked Brwoser (both Online and Offline).<br/>
3. Command Line Interaction to Online Hooked Browsers<br/>
4. Command Line Interaction to BEEF related modules<br/>
5. Fetching Browser Logs<br/>
6. Provide Brief Information about Command Modules<br/>
<br/>
<img src="https://user-images.githubusercontent.com/36254679/63011594-3dab5d00-bea6-11e9-8d81-5831c834b789.png"/>
<br/>
PyBeEF requires Beef Server and Apache Server which has to run on the same port, default port 3000 is taken by beef<br/>
To generate api key provide BeEF Credentials, default username and password is beef<br/>
<br/>
<img src="https://user-images.githubusercontent.com/36254679/63012110-45b7cc80-bea7-11e9-9af7-226248fa2d46.png"/>
<br/>
This Tool provides the list of options to the user and each option perorms different tasks<br/>
1. Get List of Sessions for active zombies<br/>
2. Information (Initial or Detailed) related to Online Hooked Browsers<br/>
3. Information (Initial or Detailed) related to Offline Hooked Browers<br/>
4. Get all the Logs performed by you<br/>
5. Get Browser related logs (active zombie browser) for already performed commands or action<br/>
6. Get List of Command Modules available in BeEF<br/>
7. Brief Explanation of each command module<br/>
8. Information about specific command module<br/>
9. Perform the Attack based on command module id provided by the user/attacker<br/>
10. Perform all attacks in one shot, where victim intervention is not required<br/>
11. Perform all attacks in one shot, where victim intervention is required (Use Edit_Modules.txt file to add information required for specific module)<br/>
12. Generate PDF Report for Complete Hooked Browser Information
<br/><br/>
<img src="https://user-images.githubusercontent.com/36254679/63012535-0b9afa80-bea8-11e9-9983-87d21db2d474.png"/>
<br/>
This Tool provides the basic knowledge on how to use Beef in real time, use this tool in ethical way.<br/>Using this tool you can get complete report (os, version, cpu, graphic, etc..) of the browser<br/>PyBeef implements a lot of testing functionalities on hooked browsers, use this tool as browser testing tool
