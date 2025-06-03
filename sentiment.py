import nltk
from nltk.corpus import movie_reviews
import random
import string

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Download dataset
nltk.download('movie_reviews')

# Load data
documents = [(list(movie_reviews.words(fileid)), category)
             for category in movie_reviews.categories()
             for fileid in movie_reviews.fileids(category)]

# Shuffle data
random.shuffle(documents)

# Preprocess data
def preprocess_text(words):
    # Lowercase, remove punctuation
    return ' '.join([w.lower() for w in words if w not in string.punctuation])

texts = [preprocess_text(doc) for doc, label in documents]
labels = [label for doc, label in documents]

# Vectorize text using Bag of Words
vectorizer = CountVectorizer()
X = vectorizer.fit_transform(texts)
y = labels

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a classifier
clf = MultinomialNB()
clf.fit(X_train, y_train)

# Predict and evaluate
y_pred = clf.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
