import os
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import urllib
import html
import joblib

class WAF(object):

    def __init__(self):
        # Load queries from text files and CSV
        good_query_list = self.get_query_list('goodqueries.txt')
        bad_query_list = self.get_query_list('badqueries.txt')
        csv_queries, csv_labels = self.get_csv_data('payload_train.csv')

        # Label text file queries (0 for good, 1 for bad)
        good_y = [0] * len(good_query_list)
        bad_y = [1] * len(bad_query_list)

        # Combine all datasets
        queries = bad_query_list + good_query_list + csv_queries
        y = bad_y + good_y + csv_labels

        # Convert queries into vectors using TF-IDF with n-grams
        self.vectorizer = TfidfVectorizer(tokenizer=self.get_ngrams)
        X = self.vectorizer.fit_transform(queries)

        # Split data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Initialize and train Logistic Regression model
        self.lgs = LogisticRegression()
        self.lgs.fit(X_train, y_train)

        print('Model accuracy: {}'.format(self.lgs.score(X_test, y_test)))

    def predict(self, new_queries):
        new_queries = [urllib.parse.unquote(url) for url in new_queries]
        X_predict = self.vectorizer.transform(new_queries)
        res = self.lgs.predict(X_predict)

        res_list = []
        for q, r in zip(new_queries, res):
            result = 'Normal request' if r == 0 else 'Malicious request'
            q_entity = html.escape(q)
            res_list.append({'url': q_entity, 'res': result})

        print("Prediction result list: {}".format(str(res_list)))
        return res_list

    def get_query_list(self, filename):
        filepath = os.path.join(os.getcwd(), filename)
        with open(filepath, 'r') as f:
            data = f.readlines()
        return list(set(urllib.parse.unquote(d.strip()) for d in data))

    def get_csv_data(self, filename):
        filepath = os.path.join(os.getcwd(), filename)
        df = pd.read_csv(filepath)
        queries = df['payload'].apply(urllib.parse.unquote).tolist()
        labels = [1 if label == 'anom' else 0 for label in df['label']]
        return queries, labels

    def get_ngrams(self, query):
        return [query[i:i + 3] for i in range(len(query) - 3)]

def waf_model_predict(url):
    filepath = os.path.join(os.getcwd(), 'lgs.pickle')
    with open(filepath, 'rb') as input_file:
        w = joblib.load(input_file)
    return w.predict(url)

if __name__ == '__main__':
    if not os.path.exists('lgs.pickle'):
        w = WAF()
        with open('lgs.pickle', 'wb') as output:
            joblib.dump(w, output)

    with open('lgs.pickle', 'rb') as input_file:
        w = joblib.load(input_file)

    test_queries = [
        'www.foo.com/id=1<script>alert(1)</script>',
        'www.foo.com/name=admin\' or 1=1',
        'abc.com/admin.php',
        '"><svg onload=confirm(1)>',
        'test/q=<a href="javascript:confirm(1)>',
        'q=../etc/passwd'
    ]

    w.predict(test_queries)
