# Real-Time-Email-Phishing-Detection
The Email Phishing Detection Application is designed to identify and analyze phishing emails using machine learning and various APIs. The application provides a user-friendly interface for fetching emails, analyzing their content, and checking the safety of links and attachments.

### Features
1. User login with email and app password
2. Fetch and display emails with phishing probability
3. Analyze individual emails for IP address details and link safety
4. Scan attachments for viruses
5. Highlight phishing areas using SHAP values for better visualization
6. API endpoints for IP threat checks and URL safety checks

### Technologies Used
1. Python (Flask)
2. Scikit-learn
3. Pandas
4. Joblib
5. SHAP (SHapley Additive exPlanations)
6. APIs (VirusTotal, AbuseIPDB,IPAPI)
7. IMAP for fetching emails

### API Endpoints
1. Fetch Emails: /fetch-emails (POST)
2. Email Details: /email/<email_id>
3. Check IP Threat: /api/ip-threat/<ip_address>
4. IP Details: /api/ip-details/<ip_address>
5. Detect Link: /api/detect-link (POST)
6. Scan Link: /api/scan-link (POST)

### Configuration
Before running the application, ensure you have the following configurations set up:

VirusTotal API Key: Replace the placeholder with your actual VirusTotal API key.
https://www.virustotal.com/gui/home/upload
AbuseIPDB API Key: Set your API key for checking IP addresses.
https://www.abuseipdb.com/account/api
IPAPI API Key: Place your geolocation api key
https://ipapi.com/dashboard?reset_access_key=1

### Training Model Script Explanation (trainModel.py)
The script is designed to train a machine learning model for detecting phishing emails. The dataset used for training is assumed to be downloaded from Kaggle, specifically a CSV file that contains email texts and their corresponding labels indicating whether they are phishing or safe.
Dataset link: https://www.kaggle.com/datasets/mohammadaoalhija/phishing-email

## Frontend Overview
#### 1. Login Page (login.html)
#### *Structure and Functionality*
HTML Structure: The login page uses a simple form that prompts the user for their email address and app password, which are required to access their email via IMAP.
Email Service Selection: Users can choose between Gmail and Outlook, each represented by a radio button with an accompanying logo.
Styling: The page features a dark theme with gradients and hover effects for buttons and labels, enhancing user experience.
Form Submission: The form submits data to the /fetch-emails endpoint, triggering the email fetching process.
*Key Features:*
Responsive Design: The layout adjusts for various screen sizes, ensuring usability on both desktop and mobile devices.
Interactive Elements: The radio buttons for email services have custom styles that respond to user interaction, providing visual feedback.

![image](https://github.com/user-attachments/assets/8c0735cc-9554-482e-9d35-23103331783e)

![image](https://github.com/user-attachments/assets/80c8190a-4a65-49de-ae72-89727c1696e8)


## 2. Fetched Emails Page (Email.html)
#### *Structure and Functionality*
Dynamic Email List: This page dynamically displays a list of fetched emails, each presented as a clickable item that reveals more information about the email.
Email Classification: Each email item displays a phishing probability bar, color-coded based on the risk level (green for safe, yellow for suspicious, red for phishing).
Load More Feature: Users can load more emails with a button that sends a fetch request for additional emails, enhancing performance by not loading everything at once.
*Key Features:*
Detail View Links: Each email links to a detailed view where users can analyze the email further.
Responsive and Interactive Design: The hover effect makes it visually engaging, with smooth transitions when hovering over email items.

![image](https://github.com/user-attachments/assets/604b903d-83fb-4139-8112-49b9e43b5e6d)

![image](https://github.com/user-attachments/assets/31ede819-0cb2-48d6-b7bd-18778086e5cd)

## 3. Email Detail Page (email_details.html)
#### *Structure and Functionality*
Comprehensive Email Information: This page presents detailed information about a selected email, including the sender, date, and phishing probability.
IP Address Analysis: Displays the sender's IP address and allows for detailed analysis, including a button to fetch and show more information about the IP.
Attachments and Links: Lists any attachments along with their security status and any links within the email, checking their safety against external APIs.
*Key Features:*
Interactive Elements: Buttons allow users to trigger analyses for IP addresses and links, with results dynamically displayed without reloading the page.
Visual Feedback: The use of badges and color-coded threat levels helps users quickly assess the safety of the email.
Additional Features:
Map Integration: Users can view the geographical location associated with the sender's IP address on Google Maps.
Link Scanning: Each link can be scanned for threats, with results displayed next to the link, providing users with immediate security feedback.

![image](https://github.com/user-attachments/assets/ea2e8b43-b734-49ab-bbb7-caa1c19520fc)

![image](https://github.com/user-attachments/assets/fd59ad96-e21e-44c0-8551-961194872ce0)

![image](https://github.com/user-attachments/assets/143632ea-ce63-44ac-b48d-fd205103dc7e)

The frontend of the Email Phishing Detection app is designed with usability, aesthetics, and interactivity in mind. By combining structured HTML, responsive design, and dynamic JavaScript functionality, the application provides a comprehensive tool for users to detect and analyze phishing attempts in their emails effectively. This not only helps users feel secure but also educates them about email safety in an engaging manner.
