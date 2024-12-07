import csv
from tabulate import tabulate

# Helper function to count occurrences
def count_occurrences(key, count_dict):
    count_dict[key] = count_dict.get(key, 0) + 1

# Function to sort a dictionary by values
def sort_dict(data, reverse=True):
    return sorted(data.items(), key=lambda x: x[1], reverse=reverse)

# Input file path and threshold
log_path = input("Enter the path to the log file: ")
threshold_input = input("Enter the flagging threshold (default is 10): ")
threshold = int(threshold_input) if threshold_input.strip() else 10

# Dictionaries for analysis
request_counts = {}
path_counts = {}
suspicious_ips = {}

# Process the log file
with open(log_path) as file:
    for line in file:
        parts = line.split()
        if len(parts) < 9:
            continue
        
        ip = parts[0]
        endpoint = parts[6]
        try:
            status = int(parts[8])
        except ValueError:
            continue
        
        # Update dictionaries
        count_occurrences(ip, request_counts)
        count_occurrences(endpoint, path_counts)
        if status >= 400:
            count_occurrences(ip, suspicious_ips)

# Display request counts
print("\nRequest Counts per IP Address:")
print(tabulate([["IP Address", "Request Count"]] + sort_dict(request_counts), headers="firstrow", tablefmt="grid"))

# Most accessed endpoint
most_accessed = max(path_counts, key=path_counts.get)
print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed}: Accessed {path_counts[most_accessed]} times")

# Suspicious activity
flagged = {ip: count for ip, count in suspicious_ips.items() if count > threshold}
print("\nSuspicious Activity Detected:")
if flagged:
    print(tabulate([["IP Address", "Failed Login Attempts"]] + sort_dict(flagged), headers="firstrow", tablefmt="grid"))
else:
    print("No IPs flagged above the threshold.")

# Save results to a CSV file
with open("log_analysis_results.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)
    
    # Save request counts
    writer.writerow(["Requests per IP Address"])
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(sort_dict(request_counts))
    
    writer.writerow([])  # Blank line
    
    # Save most accessed endpoint
    writer.writerow(["Most Frequently Accessed Endpoint"])
    writer.writerow ([most_accessed, path_counts[most_accessed]])  
    writer.writerow([])  # Blank line
    
    # Save suspicious activity
    writer.writerow(["Suspicious IPs"])
    writer.writerow(["IP Address", "Failed Login Attempts"])
    writer.writerows(sort_dict(flagged))
