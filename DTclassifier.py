from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
import pandas as pd
import pickle

# Fetch raw data
legitimate_urls = pd.read_csv("./DATA/legitimate-urls.csv")
phishing_urls = pd.read_csv("./DATA/phishing-urls.csv")

# Data preprocessing
urls = legitimate_urls.append(phishing_urls)

# dropping columns that aren't required
urls = urls.drop(urls.columns[[0,3,5]], axis=1)

# shuffling
urls = urls.sample(frac=1).reset_index(drop=True)

# dropping unlabelled entries
urls_without_labels = urls.drop('label', axis=1)
urls_without_labels.columns
labels = urls['label']


# testing ans training split

data_train, data_test, labels_train, labels_test = train_test_split(
    urls_without_labels, labels, test_size=0.20, random_state=100)


# Creating Decision Tree Model
DTModel = DecisionTreeClassifier()
DTModel.fit(data_train, labels_train)

pred_labels = DTModel.predict(data_test)

# print(list(labels_test), list(pred_labels))

cm = confusion_matrix(labels_test, pred_labels)
print(cm)
print("Accuracy: ", accuracy_score(labels_test, pred_labels))

file_name = "DecisionTreeClassifier.sav"
pickle.dump(DTModel, open(file_name, 'wb'))

# ## Random Forest

RFmodel = RandomForestClassifier()
RFmodel.fit(data_train, labels_train)
rf_pred_label = RFmodel.predict(data_test)
#print(list(labels_test)),print(list(rf_pred_label))

cm2 = confusion_matrix(labels_test, rf_pred_label)
print(cm2)
print(accuracy_score(labels_test, rf_pred_label))

file_name = "RandomForestModel.sav"
pickle.dump(RFmodel, open(file_name, 'wb'))

# Latest Output
# [[91  7]
#  [17 87]]
# Accuracy:  0.8811881188118812
# [[92  6]
#  [17 87]]
# 0.8861386138613861
