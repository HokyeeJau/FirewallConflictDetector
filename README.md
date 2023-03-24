# Firewall Conflict Detector

This detector is a simple implementation of the following paper:

```
@article{al2002design,
  title={Design and implementation of firewall policy advisor tools},
  author={Al-Shaer, Ehab and Hamed, Hazem},
  journal={DePaul University, CTI, Tech. Rep},
  volume={239},
  year={2002}
}
```
The tool can detect the extra conflicts: *over authorization* and *inactive rule*. Besides, as the requirements between **common firewalls** and **private cloud firewalls** are different, we specificially set two modes for detection.

## 1. Prerequisites

### 1.1 Environment / Testbed
The tool requires **Python3.6+**. No additional library is needed.

### 1.2 Data
Please prepare a **CSV** file containing the firewall configurations that you own.

The fields of each rule should contain: 
* `id`: the ID of the firewall rule
* `inactive`: the status of the firewall rule. By default, the rule is considered as 'active' if the field is empty, otherwise it is 'inactive'.
* `src_ip`: source IP (groups), it can be in the following formats:
  * Any source IP: `ANY`, `\*.\*.\*.\*`, `0.0.0.0`
  * Specific source IP: `10.0.102.100`
  * IP group: `10.0.102.10-10.0.255.255`
  * Mixed IP groups: `10.0.101.10,10.0.102.10-10.0.255.255,10.0.103.10-10.255.255.255`
* `src_port`: source port (groups), it can be in the following formats:
  * Any source port: `ANY`, `*`
  * Specific port: `20`, `3306`,
  * Port group: `20-22`
  * Mixed port groups: `32,99-199,2000-30000,34`
* `dst_ip`: destination IP (groups), it has the same formats as `src_ip`
* `dst_port`: destination port (groups), it not only has the same formats as `src_port` when the `protocol` is given, but also allows the combination of `protocol`
 and `dst_port`:
  * Specific comb port:`tcp_80`
  * Comb port group: `tcp_80-200`
  * Comb port groups: `tcp_80-200,udp_500-600`
* `protocol`: protocol of the firewall rule, if it is combined with `dst_port`, the tool will not check this field.
* `action`: action of the rule:
  * DENY: `0`, `n`, `no`, `deny`, `reject`, `f`
  * ACCEPT: other strings

## 2. Usage

## 2.1 Arguments
We set the arguments of the tool as follow:
```
hokyeejau@your-host> python detect.py --help
usage: detect.py [-h] [--id ID] [--inactive INACTIVE] [--src_ip SRC_IP] [--src_port SRC_PORT] [--dst_ip DST_IP] [--dst_port DST_PORT] [--protocol PROTOCOL] [--action ACTION] [--test TEST] [--sum SUM] [--fpath FPATH] [--cdir CDIR] [--workers WORKERS]
                [--first_policy FIRST_POLICY] [--private_cloud PRIVATE_CLOUD]                                                                                                                                                                           
                                                                                                                                                                                                                                                        
optional arguments:                                                                                                                                                                                                                                     
  -h, --help            show this help message and exit                                                                                                                                                                                                 
  --id ID               column of id, default 0                                                                                                                                                                                                         
  --inactive INACTIVE   column of inactive, default 2
  --src_ip SRC_IP       column of source ip addresses, default 4
  --src_port SRC_PORT   column of source ports, default 5
  --dst_ip DST_IP       column of destination ip addresses, default 7
  --dst_port DST_PORT   column of destination ports, default 9
  --protocol PROTOCOL   column of protocol, default -1 (combined with dst_port)
  --action ACTION       column of action, default 10
  --test TEST           test samples shown in the paper
  --sum SUM             if summarize the conflict reports under cdir
  --fpath FPATH         file(.csv) path containing resolved firewall rules
  --cdir CDIR           directory for holding conflict reports
  --first_policy FIRST_POLICY
                        the first line of policies in csv, default 1
  --private_cloud PRIVATE_CLOUD
                        if the firewall is belonging to private cloud
```

### 2.2 Detect Conflicts

* Detect the conflicts of the rules copied from the paper.
```shell
python3 detect.py --test=1 --sum=1 --cdir=conflicts/ --private_cloud=0
```

The conflict reports between every rule and its subsequent policies

* Detect the conflicts of the configurations given from the CSV file (common firewall)
```shell
python3 detect.py --test=0 --sum=1 --cdir=conflicts/ --private_cloud=0 --fpath=configurations.csv --cdir=conflicts/
```

Please make sure the column indexes are the same as the default ones. If not, please additionally enter the column indexes of the fields.
The indexes should be ranging from 0.

* Detect the conflicts of the configurations given from the CSV file (private cloud firewall)
```shell
python3 detect.py --test=0 --sum=1 --cdir=conflicts/ --private_cloud=1 --fpath=configurations.csv --cdir=conflicts/
```

* Generate summary report only.
It is only available when `cdir` is not empty. 
```shell
python3 detect.py --test=0 --cdir=conflicts/ --sum=1
```

### 2.3 Reports
* When the tool detects conflicts, it generates four kinds of ducoments:
  * `overauthorization.txt` containing over-authorized policy IDs,
  * `disable.txt` including inactive policy IDs,
  * `conflicst/*.json` including the bipartite policy information, field relations and conflict types.
  * `report.txt` is generated when `sum` is true, including the counts of different conflicts and their corresponding policy pair.

* The notation of different set relation in conflict reports:
  * 0: None
  * 1: Equal
  * 2: Proper subset
  * 3: Superset
  * 4: Intersection

