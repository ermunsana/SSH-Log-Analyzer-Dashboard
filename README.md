# SSH Log Analyzer Dashboard

SSH Log Analyzer Dashboard is a web application that analyzes Linux `auth.log` files and highlights failed SSH login activity.

The app lets a user upload a log file through a simple web interface. The backend parses the file, extracts failed SSH login attempts, and returns useful security information such as:

- total failed login attempts
- source IP addresses
- timestamps
- targeted usernames
- authentication methods

The app also applies simple detection rules to make the results easier to understand. It can flag:

- possible brute-force activity when one IP generates many failed login attempts
- possible username enumeration when one IP tries multiple different usernames

The frontend displays the analysis in a clear dashboard with:

- total failed login count
- top IP addresses
- suspicious IP highlights
- security alerts
- detailed failed login events

