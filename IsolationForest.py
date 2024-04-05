'''

https://quantdare.com/isolation-forest-algorithm/

dataInput will come from real data. We shall maybe say, pick out at least 20 data points before we can do abonormaly detection


The isolation number is the number of splits to isolate a data point.

An outlier will have fewer splits required.

Computation of this Isolation Number
1. Select a random point. Note that we will loop the following for ALL points.
2. For each feature (property) of all points (all variables basically), figure the min and max values of the property.
3. Select a random feature.
4. From the selected random feature, select a random value.
5. Compare the random point's feature in 3's value.
	- If the selected random value in 4. is less than this random point's feature's value: set max of the range (in 2.) to this random point's feature's value.
	- Else if the selected random value in 4. is more than this random point's feature's value: set min of the range (in 2.) to this random point's feature's value.
6. Repeat steps 3 to 5 to isolate this chosen random point. A point should only be the one inside the updated range.

The number of times you perform the repeat of steps 3 to 5: this is the isolation number.

We perform the above steps 1 to 6 for all points in the dataset. The moment we finish computation of isolation scores for all data points, we consider that to be just
for isolation tree. We will construct multiple isolation trees. Of course, the more isolation trees you have, the more accurate in anomaly detection the forest will be.

Then, after making multiple isolation trees, we will aggregate the isolation trees in the isolation forest.
We will use averaging, and Z-score.

We will use the dataset:
Bubnov, Yakov (2021), 'DNS Tunneling Queries for Binary Classification', Mendeley Data, V2, doi: 10.17632/mzn9hvdcxg.2
To build a "majority" normal data for isolation forest to reference and isolate abnormalies.


IsolationForest algorithm from scikit-learn
Parameters explained:
n_estimators: number of isolation trees. See above. Default is 100
max_samples: size of dataset (chosen number of data points) to be used for isolation trees. Default is min(256, length(dataset))
contamination: known percentage of abnormalies. Represented as a probability from 0 to 1. 
max_features: proportion of features to consider in each sample. Represented as a "probability" proportion from 0 to 1.
random_state: set to 0 for testing purposes (fixes the randomly-generated values)

Function:
predict(): output: 1 means not outlier. -1 means outlier.
'''
from sklearn.ensemble import IsolationForest
from joblib import dump, load
from dataset import loadDataset
import inspect

def buildIsolationForestQueryLength(list_, save = True):
    list_ = wrapListElementsIfPossible(list_)
    if verifyWrappedListFormat(list_):
        classifier = IsolationForest().fit(list_)
        if save:
            dump(classifier, 'IsolationForestQueryLength.joblib')

def buildIsolationForestResponseLength(list_, save = True):
    list_ = wrapListElementsIfPossible(list_)
    if verifyWrappedListFormat(list_):
        classifier = IsolationForest().fit(list_)
        if save:
            dump(classifier, 'IsolationForestResponseLength.joblib')


def loadIsolationForestQueryLength():
    try:
        return load('IsolationForestQueryLength.joblib')
    except FileNotFoundError:
        print("IsolationForestQueryLength.joblib file not found.")
        raise

def loadIsolationForestResponseLength():
    try:
        return load('IsolationForestResponseLength.joblib')
    except FileNotFoundError:
        print("IsolationForestResponseLength.joblib file not found.")
        raise


def predictQueryLength(list_): # Uses Isolation Forest algorithm to determine which points are abnormalities
    isolationForestQueryLength = loadIsolationForestQueryLength()
    list_ = wrapListElementsIfPossible(list_)
    if verifyWrappedListFormat(list_):
        results = isolationForestQueryLength.predict(list_)
        print("Abnormalities results:", results)
        return results

def predictResponseLength(list_): # Uses Isolation Forest algorithm to determine which points are abnormalities
    isolationForestResponseLength = loadIsolationForestResponseLength()
    list_ = wrapListElementsIfPossible(list_)
    if verifyWrappedListFormat(list_):
        results = isolationForestResponseLength.predict(list_)
        print("Abnormalities results:", results)
        return results

def verifyWrappedListFormat(list_):
    parentFunction = inspect.stack()[1].function # Get the caller function. Just for printing
    if not isinstance(list_, list):
        raise TypeError(f"{parentFunction}(): The input is not in a list format.")
    if not list_:
        raise ValueError(f"{parentFunction}(): The input list is empty.")
    if not all(isinstance(element, list) for element in list_):
        raise ValueError(f"{parentFunction}(): Some elements of the list are not in the list format themselves.")
    if not all(isinstance(element, (int, float)) for sublist in list_ for element in sublist):
        raise ValueError(f"{parentFunction}(): Some elements of the list are not numbers (int or float).")
    return True

def wrapListElementsIfPossible(possibleList):
    if isinstance(possibleList, list) and (not any(isinstance(element, list) for element in possibleList)):
        return [[x] for x in possibleList]
    return possibleList


try:
    isolationForestQueryLength = loadIsolationForestQueryLength()
except FileNotFoundError:
    print("Isolation Forest algorithm for query length not yet set up. Setting it up now...")
    normalQueryLengthData = loadDataset.getQueryNameLengthNormalTunnelingData()
    buildIsolationForestQueryLength(normalQueryLengthData)

    print("Isolation Forest algorithm for query length is set up and ready for prediction.")


try:
    isolationForestResponseLength = loadIsolationForestResponseLength()
except FileNotFoundError:
    print("Isolation Forest algorithm for response length not yet set up. Setting it up now...")
    normalResponseLengthData = loadDataset.getResourceRecordNameLengthNormalTunnelingData()
    buildIsolationForestResponseLength(normalResponseLengthData)

    print("Isolation Forest algorithm for response length is set up and ready for prediction.")
