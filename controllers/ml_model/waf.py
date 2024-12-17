# coding: utf-8

import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import urllib
import time
import pickle
import html
import joblib
import numpy as np
import matplotlib.pyplot as plt



class WAF(object):

    def __init__(self):
        # Load good and bad queries from text files
        good_query_list = self.get_query_list('goodqueries.txt')
        bad_query_list = self.get_query_list('badqueries.txt')
        
        # Label good queries as 0 and bad queries as 1
        good_y = [0 for i in range(len(good_query_list))]
        bad_y = [1 for i in range(len(bad_query_list))]

        # Combine the queries and their labels
        queries = bad_query_list + good_query_list
        y = bad_y + good_y

        # Convert the queries into vectors using TF-IDF with custom tokenizer (n-grams)
        self.vectorizer = TfidfVectorizer(tokenizer=self.get_ngrams)

        # Fit the vectorizer on the queries and transform the text into numerical data
        X = self.vectorizer.fit_transform(queries)

        # Split the data into training and testing sets (80/20 split)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Initialize the Logistic Regression model
        self.lgs = LogisticRegression()

        # Train the model on the training set
        self.lgs.fit(X_train, y_train)

        # Print the accuracy of the model on the test set
        print('Model accuracy: {}'.format(self.lgs.score(X_test, y_test)))
    
    # Predict whether new queries are malicious or normal
    def predict(self, new_queries):
        # Decode any URL-encoded characters in the queries
        new_queries = [urllib.parse.unquote(url) for url in new_queries]
        
        # Vectorize the new queries using the fitted vectorizer
        X_predict = self.vectorizer.transform(new_queries)
        
        # Make predictions
        res = self.lgs.predict(X_predict)

        
        # Create a list of results with query and classification
        res_list = []
        for q, r in zip(new_queries, res):
            result = 'Normal request' if r == 0 else 'Malicious request'
            q_entity = html.escape(q)  # Escape any special HTML characters
            res_list.append({'url': q_entity, 'res': result})
        
        # Print the prediction result list
        print("Prediction result list: {}".format(str(res_list)))
        
        return res_list

    # Read queries from a file and return them as a list
    def get_query_list(self, filename):
        directory = str(os.getcwd())
        filepath = directory + "/controllers/api/ml_model/" + filename
        data = open(filepath, 'r').readlines()
        query_list = []
        for d in data:
            d = str(urllib.parse.unquote(d))  # Convert URL-encoded data to a simple string
            query_list.append(d)
        return list(set(query_list))  # Remove duplicates

    # Tokenizer function to create 3-grams from each query
    def get_ngrams(self, query):
        tempQuery = str(query)
        ngrams = []
        for i in range(len(tempQuery) - 3):
            ngrams.append(tempQuery[i:i + 3])
        return ngrams

def waf_model_predict(url):
    directory = str(os.getcwd())
    filepath = directory + "/controllers/ml_model/" + "lgs.pickle"
    with open(filepath,'rb') as input:
        w = joblib.load(filepath)
    result = w.predict(url)
    return result


######################################################################






if __name__ == '__main__':
    # If the detection model file 'lgs.pickle' does not exist, train the model first
#    w = WAF()
#    with open('lgs.pickle','wb') as output:
#        joblib.dump(w, 'lgs.pickle')
#   
#
#    # Example predictions on new queries
    with open('lgs.pickle','rb') as input:
        w = joblib.load('lgs.pickle')
    print(str(os.getcwd()))
    w.predict(['www.foo.com/id=1<script>alert(1)</script>',
               'www.foo.com/name=admin\' or 1=1',
               'abc.com/admin.php',
               '"><svg onload=confirm(1)>',
               'test/q=<a href="javascript:confirm(1)>',
               'q=../etc/passwd'])
