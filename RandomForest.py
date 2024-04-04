'''
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
I used the following dataset to build the encoding: 
https://github.com/csirtgadgets/tf-domains-example/tree/master

'''

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import numpy as np

#TODO: Input in the dataset above.
exampleSuspiciousDomains = ['u9hdsihsd.com', 'aoisfh3hweui.abc', 'adsiufn9wq.qr', 'zxcihvoifusgn.to']

exampleSafeDomains = ['google.com', 'yahoo.com', 'amazon.com', 'microsoft.com', 'youtube.com', 'facebook.com']

# We will mark 1 for suspicious domains, 0 for real domains. Purpose is to label and teach the model.
labels = [1] * len(exampleSuspiciousDomains) + [0] * len(exampleSafeDomains)

print("Labels", labels)



allDomains = exampleSuspiciousDomains +exampleSafeDomains
print("domains list", allDomains)

ngramRange = (2, 4)  # I hypothesise that there are 2 characters to 4 characters in each subdomain / TLD

# The analyser parameter determines whether a word should be encoded or just individual characters
# Since domain names can be jumbled, i used characters encoding.
countVectoriser = CountVectorizer(analyzer='char', ngram_range=ngramRange)

# Learn the vocabulary dictionary and return document-term matrix.
X = countVectoriser.fit_transform(allDomains)

XTrain, XTest, yTrain, yTest = train_test_split(X, labels, test_size=0.2, random_state=42)

classifier = RandomForestClassifier(n_estimators=100, random_state=1)
classifier.fit(XTrain, yTrain) # Learns actual output from input

yPredictions = classifier.predict(XTest) # Tests on test dataset. Used for evaluation

print("Accuracy:", accuracy_score(yTest, yPredictions))
print("\n\n\n")
print("Classification Report:", classification_report(yTest, yPredictions))

# These new domains: #TODO: Plug in the domains to test out.
newDomains = ['xyc123.com', 'google.com', 'abcxyz.org', 'asdhfuoihas.to']


Xnew = countVectoriser.transform(newDomains)
predictions = classifier.predict(Xnew)

for domain, prediction in zip(newDomains, predictions):
    if prediction == 1:
        print(f"{domain}: DGA detected")
    else:
        print(f"{domain}: Legitimate")
