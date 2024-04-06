'''
Random Forest algorithm is more suitable for categorical tasks; whereas Isolation Forest algorithm is more suitable for detecting anomalies (in a feature)

https://www.analyticsvidhya.com/blog/2021/06/understanding-random-forest/#:~:text=Random%20forest%20algorithm%20is%20an,both%20classification%20and%20regression%20problems.
https://www.youtube.com/watch?v=_3ahmI5vpKY&list=PLeo1K3hjS3uuvuAXhYjV2lMEShq2UYSwX&index=13

I used some concepts explained very well in the video to interpret encoding of the domain names into quantifiable values.

The key thing is, we use what we know, what we best know, to make a best guess.
We select the features we think best represents the identification of a proper word or not.
We select a set of variables that we think best classifies a word as proper or not.
This approach, we extend to domain names. Meaning to say: we analyse how we see a domain string as suspicious and a domain string as not.

We should observe minutiae of the the domain string - the existence of actual words; the grammatical structure ... and there could be infinitely many attributes.
But we pick out the ones that we think best quantifies the suspiciousness of a domain name - the "jumbledness" of characters.

After encoding, the step above, we will have a sort of quantifiable measure already, off the get-go, of how "jumbled" the characters are in a given domain name.

The next step is to optimise this classification process of any given string.

Note that the encoding step is always the most important aspect; a bad selection of features will result always in poor performance.
So we need to make good "intuitive" guesses on which features are most prominent in determining the "jumbledness" of words. 

After encoding, we can perform the optimisation of its ascribed values via machine learning - random forests.

General goal of Random Forest algorithm in DGA detection:
We can detect out suspicious domain names. Then flag them out.

Algorithm:
1. Convert the text to a sort of numerical measure. So we can eventually input to the RandomForest algorithm
We do this using CountVectorizer

2. CountVectorizer.fit_transform() generates the vocabulary that encodes the tokens.
It studies sequences that exists in the provided data.
The `n` in n-gram refers to the sequences of characters as seen in the provided data.
It will use these seen character sequences, and store it as a "word" in its vocabulary.

fit_transform() does fit() and transform() sequentially.
fit() creates a count for each token.
transform() converts this entire mapping (dictionary map) into simply a matrix. Numerical form.

3. With the above, we conduct a train-test split on the dataset.
Purpose is to purely evaluate whether the classifier is working 

4. n_estimators parameter represents the number of decision trees used to
5. random_state toggles whether to preserve the randomness. Its existence implies that the randomly generated values
should be preserved.

The Random Forest algorithm consists of n_estimators number of decision trees.
The algorithm will use decision trees. The concept of decision trees is what drives the algorithm:
1.You simply have a threshold value for a feature.
2. For each data point: if the data point's feature surpasses this threshold value, classify it as group one.
3. Repeat for each data point.
4. For data points not classified in group one, classify them as in group two.

In this library; the process is more complex.

The figuring out of the threshold value for each feature is abstracted away.

But the idea of it is to find a value for each feature such that a pure split is achieved:
Or more so, we aim to minimise entropy, which is a formula that computes how much uncertainty there is in a chosen 
threshold value's split.

A split in the dataset that results in leaf nodes containing only one class or category of the target variable.

In other words, we find a threshold value for each feature such that this value applied as a threshold value
will split the data points in the subsample that results in the lowest entropy values.

As the entropy value approaches 0, the split approaches a pure split.

Significance of a pure split and or lower entropy:

A value that splits with the lowest entropy out of all values implies that this value best categorises the data points
in the provided data set FOR that particular feature.

But how do we decide on the order of features in a decision tree to split the dataset?
The order is also determined in the same vein as how we determine the best threshold value: compute the entropy value
and we find the ordering that best minimises it.

This finding of optimal ordering of features to split the dataset and threshold values used is auto-computed and abstracted
away in sklearn.

classifier = RandomForestClassifier(n_estimators=100, random_state=1)
classifier.fit(XTrain, yTrain)

But the idea stays true and the same as explained.

Interpretation of classification results from train test split.
Precision: proportion of true positives out of all (true and false) positives.

Recall: actual true positive rate. Higher values = better. Perfect recall is 1.0
This is actually true positives / (true positives + false negatives)

F1 score: Balances precision and recall



Random Forest algorithm is a supervised machine learning algorithm. It needs training dataset.
I used the following datasets to build the encoding: 
https://github.com/csirtgadgets/tf-domains-example/tree/master
Bubnov, Yakov (2021), 'DNS Tunneling Queries for Binary Classification', Mendeley Data, V2, doi: 10.17632/mzn9hvdcxg.2

'''

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


# https://scikit-learn.org/stable/model_persistence.html
# We save the classifier so we do not have to keep retraining it.
from joblib import dump, load
from dataset import loadDataset

def trainRandomForestClassifierQueryResponse(labels, encodedData, testSize = 0.2, fixRandom = True, n_estimators = 100 ):

    # encodedData has two flavours: 
    # 1. Query: df[['qd_qtype', 'qd_qname_len']] or
    # 2. Response: df[['ar_type', 'ar_rdata_len']]
    # Since their training methods are more or less the same, i can re-use this function.

    # Labels: 0 means non-malicious, 1 means malicious
    XTrain, XTest,yTrain, yTest, classifier = None, None, None, None, None

    if fixRandom:
        XTrain, XTest, yTrain, yTest = train_test_split(encodedData, labels, test_size=testSize, random_state=1)

        classifier = RandomForestClassifier(n_estimators=100, random_state=1)
    else: 
        XTrain, XTest, yTrain, yTest = train_test_split(encodedData, labels, test_size=testSize)

        classifier = RandomForestClassifier(n_estimators=100)

    classifier.fit(XTrain, yTrain) # Learns actual output from input

    yPredictions = classifier.predict(XTest) # Tests on test dataset. Used for evaluation

    print("Accuracy:", accuracy_score(yTest, yPredictions))
    print("\n\n\n")
    print("Classification Report:", classification_report(yTest, yPredictions))

    return classifier

def trainRandomForestClassifierDomainName(whiteList, blackList, ngramRangeTupleInclusive, testSize = 0.2, save = True, fixRandom = True, n_estimators = 100):

    # We will mark 1 for whitelisted domains, 0 for blacklisted domains. Purpose is to label and teach the model.
    labels = [1] * len(whiteList) + [0] * len(blackList)

    allDomains = whiteList + blackList

    ngramRange = ngramRangeTupleInclusive 

    # The analyser parameter determines whether a word should be encoded or just individual characters
    # Since domain names can be jumbled, i used characters encoding.
    countVectoriser = CountVectorizer(analyzer='char', ngram_range=ngramRange)

    # Learn the vocabulary dictionary and return document-term matrix.
    X = countVectoriser.fit_transform(allDomains)

    XTrain, XTest,yTrain, yTest, classifier = None, None, None, None, None

    if fixRandom:
        XTrain, XTest, yTrain, yTest = train_test_split(X, labels, test_size=testSize, random_state=1)

        classifier = RandomForestClassifier(n_estimators=100, random_state=1)
    else: 
        XTrain, XTest, yTrain, yTest = train_test_split(X, labels, test_size=testSize)

        classifier = RandomForestClassifier(n_estimators=100)

    classifier.fit(XTrain, yTrain) # Learns actual output from input

    yPredictions = classifier.predict(XTest) # Tests on test dataset. Used for evaluation

    print("Accuracy:", accuracy_score(yTest, yPredictions))
    print("\n\n\n")
    print("Classification Report:", classification_report(yTest, yPredictions))


    if save:
        dump(countVectoriser, 'CountVectoriser.joblib')
        dump(classifier, 'RandomForestDomainNameClassifier.joblib')

def loadCountVectoriser():
    try:
        return load('CountVectoriser.joblib') 
    except FileNotFoundError:
        print("CountVectoriser.joblib file not found.")
        raise

def loadRandomForestQueryClassifier():
    
    try:
        return load('RandomForestQueryClassifier.joblib') 
    except FileNotFoundError:
        print("RandomForestQueryClassifier.joblib file not found.")
        raise

def loadRandomForestResponseClassifier():
    
    try:
        return load('RandomForestResponseClassifier.joblib') 
    except FileNotFoundError:
        print("RandomForestResponseClassifier.joblib file not found.")
        raise

def loadRandomForestDomainNameClassifier():
    
    try:
        return load('RandomForestDomainNameClassifier.joblib') 
    except FileNotFoundError:
        print("RandomForestDomainNameClassifier.joblib file not found.")
        raise

def predictQueryLength(encodedPacketQuery):
    classifier = loadRandomForestQueryClassifier()
    predictions = classifier.predict(encodedPacketQuery)
    for prediction in predictions:
        if prediction == 0:
            print("Random Forest (Query Length): NORMAL")
        else:
            print("Random Forest (Query Length): ABNORMALY")

def predictResponseLength(encodedPacketResponse):
    classifier = loadRandomForestResponseClassifier()

    predictions = classifier.predict(encodedPacketResponse)
    for prediction in predictions:
        if prediction == 0:
            print("Random Forest (Response Length): NORMAL")
        else:
            print("Random Forest (Response Length): ABNORMALY")

def predictDomainName(newDomainsInList):
    countVectoriser = loadCountVectoriser()
    classifier = loadRandomForestDomainNameClassifier()
    Xnew = countVectoriser.transform(newDomainsInList)

    predictions = classifier.predict(Xnew)
    for domain, prediction in zip(newDomainsInList, predictions):
        if prediction == 0:
            print(f"Random Forest (Domain Name): ABNORMALY")
        else:
            print(f"Random Forest (Domain Name): NORMAL")


print("Checking if Random Forest classifier for domain name is built...")
try:
    countVectoriser = loadCountVectoriser()
    classifier = loadRandomForestDomainNameClassifier()
except FileNotFoundError:

    print("Random Forest classifier for domain name is not yet built. Building it now...")
    # I hypothesise that there are commonly there are 2 to 4 characters in each subdomain / TLD
    # So the following ngram shall detect sequences of 2 to 4 characters and build a vocabulary out of it.
    ngramRange = (2,4)

    whiteListedDomains, blackListedDomains = loadDataset.getWhiteBlackListDataset()

    trainRandomForestClassifierDomainName(whiteListedDomains, blackListedDomains, ngramRange)

print("The Random Forest classifier for domain name is already built and ready for prediction.\n")

print("Checking if Random Forest classifier for query checks is built...")
try:
    classifier = loadRandomForestQueryClassifier()
except FileNotFoundError:
    print("Random Forest classifier for query checks is not yet built. Building it now...")
    labels, encodedData = loadDataset.getQueryAndLengthDataset()
    classifier = trainRandomForestClassifierQueryResponse(labels, encodedData)
    dump(classifier, 'RandomForestQueryClassifier.joblib')

print("The Random Forest classifier for query checks is already built and ready for prediction.\n")

print("Checking if Random Forest classifier for response checks is built...")
try:
    classifier = loadRandomForestResponseClassifier()
except FileNotFoundError:
    print("Random Forest classifier for response checks is not yet built. Building it now...")
    labels, encodedData = loadDataset.getResponseAndLengthDataset()
    classifier = trainRandomForestClassifierQueryResponse(labels, encodedData)

    dump(classifier, 'RandomForestResponseClassifier.joblib')
print("The Random Forest classifier for response checks is already built and ready for prediction.\n")


'''

# Now we can test we any domains in a list form:

validDomains = [
    "example.com",
    "amazon.com",
    "microsoft.com",
    "twitter.com",
    "instagram.com",
    "wikipedia.org",
    "reddit.com",
    "stackoverflow.com",
    "github.com",
    "yahoo.com",
    "www.google.com",
    "mail.yahoo.com",
    "shopping.amazon.com",
    "blog.wordpress.com",
    "news.cnn.com",
    "support.apple.com",
    "drive.google.com",
    "login.microsoft.com",
    "images.google.com",
    "mail.google.com",
    "store.apple.com",
    "calendar.google.com",
    "maps.google.com",
    "mail.live.com",
    "docs.google.com",
    "mail.yahoo.co.uk"
]

suspiciousDomains = [
    "u3rv8p.zxi9mf.ow6.info.oifsdug8du",
    "a7d5xasdq2v6h4.t6w8e9.ds.sp9o8i7zzdshuixh",
    "j3n5k7.x8c9v2.y1vdsdrdsadsg.l0asdm9n8",
    "f8r7w4sdasvdsu2i3o1.e5r6t7.d.k9j8h7adsd",
    "q6e5d4r3vdsvd546546svdsvs5423dvsdv2y1z9.r8q7w6.adsfdsfd.p0o9i8hpifdgihu.2721853",
    "m4b6v2.n9c7x3.ow6d8a.cos435m.b3v5n7",
    "k7i8h9.gfds3f4d5.t6r7e8.hjkhjb435jkjiszdsfsdf.j2k3l4",
    "s9d8ffsd7g6.h5j4k3sfdrg.q2w3e4.net.z1x9c8",
    "p6o5i4u3.y8t7r6.qfd2w3e4.dsdhkh.v9b8n7",
    "w2e3r4tf4.b5n6m7.q8w9e0.org.d9s8a7",
    "l5k6jfsdf7.q8w9e0.o1i2u3.biadsz.f4d5s6",
    "n2b3sdfdsdm4.p5osdffd6i7.y8t9r0.nehgft.g1h2j3",
    "i9u8y7.q6w5e4.r3t2y1.orfg.f4d5s6",
    "t4r5ed3m4.q5w6e7.t8r9y0.orgfhg.g1h2j3",
    "q8w9e0rfsdsf1.t2fdy3u4.i5o6p7.inf21fo.f8d9s0",
    "a9s8dsdf7f6.x5c4v3.z2x1c9.ne21t.b8n7m6",
    "o3i4u5dss7rfdsde9w0q1sdfdfi5gsz.f2d3s4",
    "j1k2l3.g4h5j6.e7d8f9.apsdiufiauds9fusd.v0b9n8",
    "u3i4ofsdsffd5y6.e7w8r9.siaih.u0i1o2",
    "o3i4u5.p6o7i8.r9t0y1.lifeahu.q2w3e4",
    "a9sfs4b5sf4s5d6.r7t8y9.lifeasd.f0b1n2",
    "p9o8i7f.fds.f6g5h4.j3k2l1.net.z0x9c8",
    "ef8st9fdsy0u1i2.o3p4i5.biffdsfz.m6n7b8",
    "w9e8r7.t6yf5u4.z3x2c1.dsfd.q0o9i8",
    "a9sd8s9d0.r1t2y3.dsbiz.asds344.dad.fds323.hgf495893.af",
    "s3d4.f5f.dfsd1t2y3.u4i5o6p7.adfdsfds767fsd.a8s9d0",
    "d4f5gf6.q7w8e9.r1t2ydfsr1t2y3.daf.u4i5o6",
    "q8w9e0.r1t2ff.dy3.u4i5o6p7.com.a8s9d0",
    "dsfdf5sfd6.q7w8e9.r1t2y3.bdsdfiz.u4i5o6",
    "w5e.6r7.q8w9e0.r1t2y3.infodasfsf.u4i5o6"
]


predictDomainName(validDomains)
predictDomainName(suspiciousDomains)

'''