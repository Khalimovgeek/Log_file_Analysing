# Log File Analysis Program
This program is designed to analyze log files and identify suspicious login attempts. It also helps in identifying frequently accessed endpoints and counting the number of requests per user. The results are generated in both a tabular format and saved into a CSV file, providing a convenient way to keep records for further analysis.

# How It Works:
 ## 1.User Input:

Upon running the program, it asks for the path of the log file and a threshold count for flagging IP addresses (if the threshold is not provided, it defaults to 10).

## 2.Data Processing:

The program processes the log file to categorize data into:

### * Requests per user (IP): The number of times each IP address makes a request.

### * Most Frequently Accessed Endpoints: The paths that are most requested across all users.

### * Suspicious Activity (Failed Login Attempts): IPs that failed to login above the threshold value.

## 3.Output:

After processing, the results are displayed in tables, making it easy to read and interpret.
The analysis is also saved into a CSV file for record-keeping and further review.
