# Fun with Mitre-Att&ck

Data based on MITRE Att&ck Enterprise JSON https://attack.mitre.org/resources/working-with-attack/

JSON Data is parsed and analysed with Splunk. 

Splunk TA coming soon. (Modular Input to ingest Data without the need of preprocessing, sourcetypes and all the things)

## Similar Work

https://github.com/rabobank-cdc/DeTTECT

https://docs.splunksecurityessentials.com/user/productionalize/operationalize_mitre_attack/


## MITRE Att&ck - Techniques per data source
x_mitre_data_sources|count
------------ | -------------
Process monitoring|300
Process command-line parameters|189
File monitoring|182
Packet capture|79
API monitoring|75
Netflow/Enclave netflow|66
Process use of network|64
Authentication logs|61
Windows Registry|56
Network protocol analysis|53
Windows event logs|48
DLL monitoring|36
AWS CloudTrail logs|32
Azure activity logs|32
Stackdriver logs|27
Binary file metadata|26
SSL/TLS inspection|24
Loaded DLLs|23
PowerShell logs|23
Network device logs|20
Mail server|15
Network intrusion detection system|15
Application logs|12
GCP audit logs|12
Office 365 account logs|12
Email gateway|11
Web logs|11
Anti-virus|10
System calls|10
Malware reverse engineering|9
Web proxy|9
DNS records|8
Office 365 audit logs|8
Web application firewall logs|8
Data loss prevention|7
Host network interface|7
Kernel drivers|6
BIOS|5
Environment variable|5
Network device configuration|5
Services|5
Social media monitoring|5
Access tokens|4
Component firmware|4
Network device run-time memory|4
OAuth audit logs|4
Office 365 trace logs|4
Sensor health and status|4
Third-party application logs|4
User interface|4
Windows Error Reporting|4
Detonation chamber|3
Disk forensics|3
EFI|3
MBR|3
Asset management|2
Network device command history|2
SSL/TLS certificates|2
VBR|2
WMI Objects|2
Browser extensions|1
Digital certificate logs|1
Domain registration|1
Named Pipes|1


## MITRE Att&ck - Techniques per data source
![test](https://github.com/hgrow1/Mitre-Att-ck-Analytics/blob/main/Number%20of%20MITRE%20Att%26ck%20techniques%20per%20data%20source.PNG)

```
index=main sourcetype="mitre:enterprise_attack:json"
 type="attack-pattern"
 | chart count by "x_mitre_data_sources{}" | sort - count
```

## MITRE Att&ck - Techniques may covered by Sysmon

![test](https://github.com/hgrow1/Mitre-Att-ck-Analytics/blob/main/Aggregated%20Techniques%20covered%20by%20Sysmon.PNG)

```
index=main sourcetype="mitre:enterprise_attack:json"
 type="attack-pattern" 
| stats count  by "x_mitre_data_sources{}" 
| rename "x_mitre_data_sources{}" AS data_source 
| sort - count
| eval source = case (
match(data_source,"Process"),"Sysmon",
match(data_source,"File monitoring"),"Sysmon",
match(data_source,"Windows Registry"),"Sysmon",
match(data_source,"DLL"),"Sysmon")
| eventstats sum(count) AS techniques_total
| rename count AS techniques_count
| eval source = coalesce(source,data_source)
| eventstats sum(techniques_count) AS count by source
| eval covarage=round(count/techniques_total*100,2)
| stats avg(covarage) AS count by source
```

