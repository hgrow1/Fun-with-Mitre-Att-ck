# Mitre-Att-ck-Analytics


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

