import re
import csv
from collections import Counter, defaultdict

def parse_log_file(file_path):
    with open(file_path, 'r') as log_file:
        log_lines = log_file.readlines()
    return log_lines

def count_requests_per_ip(log_lines):
    ip_pattern = r'^([\d\.]+)'
    ip_counter = Counter(re.match(ip_pattern, line).group(1) for line in log_lines)
    sorted_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
    return sorted_ips

def most_frequently_accessed_endpoint(log_lines):
    endpoint_pattern = r'"[A-Z]+\s(/[\w/-]*)'
    endpoints = [re.search(endpoint_pattern, line).group(1) for line in log_lines if re.search(endpoint_pattern, line)]
    endpoint_counter = Counter(endpoints)
    most_common = endpoint_counter.most_common(1)
    return most_common[0] if most_common else None

def detect_suspicious_activity(log_lines, threshold=10):
    failed_login_pattern = r'^([\d\.]+).+"POST\s/login.+401'
    failed_ips = [re.match(failed_login_pattern, line).group(1) for line in log_lines if re.match(failed_login_pattern, line)]
    failed_counter = Counter(failed_ips)
    suspicious_ips = {ip: count for ip, count in failed_counter.items() if count > threshold}
    return suspicious_ips

def save_to_csv(file_name, requests_per_ip, most_accessed_endpoint, suspicious_activities):
    with open(file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(requests_per_ip)
        writer.writerow([])

        # Write Most Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint"])
        if most_accessed_endpoint:
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(most_accessed_endpoint)
        writer.writerow([])

        # Write Suspicious Activities
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

def main():
    log_file_path = 'sample.log'
    output_csv = 'log_analysis_results.csv'

    # Parse log file
    log_lines = parse_log_file(log_file_path)

    # Analyze logs
    requests_per_ip = count_requests_per_ip(log_lines)
    most_accessed_endpoint = most_frequently_accessed_endpoint(log_lines)
    suspicious_activities = detect_suspicious_activity(log_lines)

    # Display results
    print("Requests per IP Address:")
    for ip, count in requests_per_ip:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        endpoint, count = most_accessed_endpoint
        print(f"{endpoint} (Accessed {count} times)")
    else:
        print("No endpoints found.")

    print("\nSuspicious Activity Detected:")
    if suspicious_activities:
        for ip, count in suspicious_activities.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activities detected.")

    # Save results to CSV
    save_to_csv(output_csv, requests_per_ip, most_accessed_endpoint, suspicious_activities)
    print(f"\nResults saved to {output_csv}")

if __name__ == "__main__":
    main()
