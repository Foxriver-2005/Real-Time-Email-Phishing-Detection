import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
import joblib

# Load your dataset
df = pd.read_csv('Datasets/Phishing_Email_2.csv')  # Adjust the path if needed

# Print the column names to inspect them
print("Column names:", df.columns)

# Ensure your dataset has 'Email Text' and 'Email Type' columns
if 'Email Text' not in df.columns or 'Email Type' not in df.columns:
    print("Error: The required columns 'Email Text' and/or 'Email Type' are missing in the dataset")
    print("Available columns:", df.columns)
else:
    # Fill NaN values in 'Email Text' with a placeholder
    df['Email Text'] = df['Email Text'].fillna('')

    X = df['Email Text']
    y = df['Email Type']

    # Split the data into training and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    # Create a pipeline that combines a TF-IDF vectorizer with a Naive Bayes classifier
    model = make_pipeline(TfidfVectorizer(), MultinomialNB())

    # Train the model
    model.fit(X_train, y_train)

    # Save the model to a file
    joblib.dump(model, 'model/email_classifier.pkl')

    print("Model training complete and saved to model/email_classifier.pkl")
