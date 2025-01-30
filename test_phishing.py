
# coding: utf-8

# In[12]:


import joblib as job
import numpy as np
import sys
from feature import FeatureExtraction  # Ensure this module exists

def check_phishing(url):
    """Extract features and predict if the URL is phishing or safe."""
    
    obj = FeatureExtraction(url)
    x = np.array(obj.getFeaturesList()).reshape(1, 30)  # Reshape for model input
    
    model = job.load('model_rf.joblib')  # Load trained model
    
    y_pred = model.predict(x)[0]  # Predict phishing or safe
    return y_pred

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: No URL provided")
    else:
        url = sys.argv[1]
        prediction = check_phishing(url)
        print(prediction)  # Make sure only this is printed
 # Ensure output is printed for subprocess

