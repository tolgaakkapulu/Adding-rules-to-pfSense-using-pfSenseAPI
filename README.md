# Adding-rules-to-pfSense-using-pfSenseAPI

Alias is created with the source IP parameter information from the parameters specified in use. The destination IP is added to the alias created with the source IP name. After the created alias, the rule is created in pfSense so that the related source IP is blocked from going to the created alias.

<b>NOTE:</b> If the same source IP parameter is entered, the rule will not be created. The alias will be updated by adding the relevant destination IP in alias.
<br><br>
<b>Installing the API in pfSense</b>
- pkg add https://github.com/jaredhendrickson13/pfsense-api/releases/latest/download/pfSense-2.4-pkg-API.txz
- /etc/rc.restart_webgui

<b>Usage</b>
- python3 pfSense-api.py SOURCE DESTINATION

<b>Example</b>
  - python3 pfSense-api.py 10.10.10.10 10.10.10.20
