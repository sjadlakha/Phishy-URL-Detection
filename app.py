from feature_extraction import getFeatures
import pickle
import sys

# data = getFeatures(sys.argv[1])

data = getFeatures(input())
DTModel = pickle.load(open(
    '/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/DecisionTreeClassifier.sav', 'rb'))

RFModel = pickle.load(open(
    '/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/RandomForestModel.sav', 'rb'))

DT_result = DTModel.predict(data)
RF_result = RFModel.predict(data)
print(DT_result[0])
# print(RF_result)

# Decision Tree is performing better

# TODO: Improve performence of Decision tree model
# TODO: Connect node app to python app`