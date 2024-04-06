# DNS-Monitoring-and-IDS

### To Run:

python -m venv .

cd Scripts

activate

cd ..

pip install -r requirement.txt

python DNSScan.py

### Note:

When you first run DNSRealTimeScans.py, it will take some time to build the Random Forest Classifier. After building, it should save the classifier as RandomForestDomainNameClassifier.joblib in the root.

The file was too large to be uploaded on GitHub, hence is omitted is this remote repository.

### Datasets:

Datasets used: 

1. https://github.com/csirtgadgets/tf-domains-example/tree/master
/dataset/whitelist
/dataset/blacklist

2. https://data.mendeley.com/datasets/mzn9hvdcxg/2:
Bubnov, Yakov (2021), 'DNS Tunneling Queries for Binary Classification', Mendeley Data, V2, doi: 10.17632/mzn9hvdcxg.2
/dataset/binary

