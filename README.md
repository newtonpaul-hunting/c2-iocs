# C2 Sightings IOC Feed

Live feed of confirmed C2 infrastructure identified by active scanning. Updated automatically when new entries are published to [C2 Hunter](https://c2-hunter.newtonpaul.com).

## Feed

**URL:** `https://raw.githubusercontent.com/newtonpaul-hunting/c2-iocs/main/c2_sightings.csv`

## Format

CSV with header row:

| Column | Description |
|--------|-------------|
| IP | IPv4 address of the C2 server |
| Framework | C2 framework (e.g. cobalt-strike, sliver, havoc) |
| Port | Listening port |
| Country | ISO-3166-1 alpha-2 country code |
| PublishedAt | Date first published (YYYY-MM-DD) |

## Microsoft Defender for Endpoint — Advanced Hunting

```kql
let C2IOCs = (externaldata(IP:string, Framework:string, Port:int, Country:string, PublishedAt:string)
    [@"https://raw.githubusercontent.com/newtonpaul-hunting/c2-iocs/main/c2_sightings.csv"]
    with (ignoreFirstRecord=true, format="csv"));
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIP in ((C2IOCs | project IP))
| join kind=leftouter (C2IOCs) on $left.RemoteIP == $right.IP
| project
    Timestamp,
    DeviceName,
    DeviceId,
    LocalIP,
    RemoteIP,
    RemotePort,
    Framework,
    Country,
    PublishedAt,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

