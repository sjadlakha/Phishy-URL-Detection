from feature_extraction import getFeatures
import pickle
import sys

# data = getFeatures(sys.argv[1])

# For development
data = getFeatures('en.wikipedia.org')
DTModel = pickle.load(open(
    '/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/DecisionTreeClassifier.sav', 'rb'))

RFModel = pickle.load(open(
    '/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/RandomForestModel.sav', 'rb'))

DT_result = DTModel.predict(data)
RF_result = RFModel.predict(data)
print(str(DT_result[0]), flush = True)


# Decision Tree is performing better

# TODO: Improve performance of Decision tree model
