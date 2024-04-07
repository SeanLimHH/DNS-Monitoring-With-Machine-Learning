# DNS Monitoring with Machine Learning

### Set Up

1. Run setup.bat

### API Keys - IMPORTANT

The key values are in .env

If you ran setup.bat, you would have been prompted to enter your API key.
Otherwise, just edit manually in .env, for the corresponding key.

You have to input the API keys for VirusTotal API calls for some functionality to work.

Here is the guide to obtain your API key:

https://docs.virustotal.com/docs/please-give-me-an-api-key

With regards to URLScan, it is another database that I had intended to reference.

As of now, i chose not to use it. The reason being is that it does not support more
complex scans like VirusTotal. Furthermore, VirusTotal does cover quite a few other
providers, hence is a very strong reference point as its own already.

Thus, for URLScan, you can leave the API key empty.

Do note that there is a limited amount of calls you can make; after which, the scan results would just show 'None'.

### Activating the Python virtual environment

cd Scripts && activate && cd ..

### Deactivating the Python virtual environment

cd Scripts && deactivate && cd ..

### Running the program - perform this only after Set Up!

Ensure that you are in the virtual environment before running the following!

1. run.pyw
2. When running the Real-Time Monitoring for the first time, it will take a long time. This is because it is building the model.

It is possible to change the duration of the building of the classifier: ngram range in RandomForest.py.

It is a tuple: (minLengthSequence, maxLengthSequence)

You can set them both the same value.

The larger the range between the minimum and maximum length sequence, the longer it takes.

The larger the values for either minimum length sequence or maximum length sequence, the longer it takes.

A fast ngram model would use (2,2) or (3,3); if you are strapped on time.

This value determines length of all sequences of characters that are seen, as to which, a huge huge huge vocabulary builds upon.

After building, it should save the classifier as RandomForestDomainNameClassifier.joblib in the root.

I have the file locally. It was too large to be uploaded on GitHub, hence is omitted im this remote repository.

### Datasets

1. https://github.com/csirtgadgets/tf-domains-example/tree/master

Dataset locations:

/dataset/whitelist

/dataset/blacklist

2. https://data.mendeley.com/datasets/mzn9hvdcxg/2:
   Bubnov, Yakov (2021), 'DNS Tunneling Queries for Binary Classification', Mendeley Data, V2, doi: 10.17632/mzn9hvdcxg.2

Dataset locations:

/dataset/binary
