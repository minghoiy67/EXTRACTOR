import re
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(
    filename="error.log",
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def is_valid_email(email):
    # Validate email using a stricter regex
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False

    # Exclude emails containing specific keywords
    excluded_keywords = [
        "info", "news", "support", "contact", ".edu", ".gov", "privacy", 
        "frontdesk", "help", ".png", "school", "customerservices", 
        "firstname", "compliance", "career", "example", "feedback", 
        "subscriptions", "customercare", "editor", "questions", "@gmail.com"
    ]
    return not any(keyword in email.lower() for keyword in excluded_keywords)

def extract_names_and_emails(content):
    """Extract names and emails from the content."""
    # Regex to match names (e.g., "John Doe") and emails
    name_email_regex = r'([A-Z][a-z]+(?: [A-Z][a-z]+)?)\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>'
    email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    names_and_emails = re.findall(name_email_regex, content)
    emails = re.findall(email_regex, content)

    result = []
    found_emails = set()

    # Add names and emails if both are found
    for name, email in names_and_emails:
        if is_valid_email(email):
            result.append(f"{name} <{email}>")
            found_emails.add(email)

    # Add emails alone if no name is associated
    for email in emails:
        if email not in found_emails and is_valid_email(email):
            result.append(email)

    return result

def extract_emails_from_url(url):
    try:
        print(f"Processing URL: {url}")
        response = requests.get(url, timeout=10)  # Add timeout for faster failure
        response.raise_for_status()
        content = response.text

        # Extract names and emails
        return set(extract_names_and_emails(content))
    except requests.RequestException as e:
        logging.error(f"Error fetching URL {url}: {e}")
        print(f"Error fetching URL {url}. Check error.log for details.")
        return set()

def extract_links_from_url(url, base_url):
    try:
        response = requests.get(url, timeout=10)  # Add timeout for faster failure
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        return {
            urljoin(base_url, a_tag["href"])
            for a_tag in soup.find_all("a", href=True)
            if urljoin(base_url, a_tag["href"]).startswith("http")
        }
    except requests.RequestException as e:
        logging.error(f"Error fetching links from {url}: {e}")
        print(f"Error fetching links from {url}. Check error.log for details.")
        return set()

def extract_emails_in_depth(url, depth=1, visited=None, output_file=None, saved_emails=None):
    if visited is None:
        visited = set()
    if saved_emails is None:
        saved_emails = set()
    if depth < 0 or url in visited:
        return set()
    visited.add(url)

    emails = extract_emails_from_url(url)
    if output_file:
        with open(output_file, "a") as file:
            for email in emails:
                if email not in saved_emails:
                    file.write(email + "\n")
                    saved_emails.add(email)
                    print(f"Saved: {email} (Total saved: {len(saved_emails)})")

    if depth > 0:
        links = extract_links_from_url(url, url)
        for link in links:
            extract_emails_in_depth(link, depth - 1, visited, output_file, saved_emails)
    return emails

def extract_emails_from_urls(urls, depth=1, output_file=None):
    saved_emails = set()
    visited = set()
    with ThreadPoolExecutor(max_workers=10) as executor:  # Use threading for parallel processing
        futures = [
            executor.submit(extract_emails_in_depth, url, depth, visited, output_file, saved_emails)
            for url in urls
        ]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error in thread execution: {e}")
                print("Error occurred during thread execution. Check error.log for details.")

if __name__ == "__main__":
    try:
        # Specify encoding to handle potential UnicodeDecodeError
        with open("links.txt", "r", encoding="utf-8") as file:
            urls = list(set(line.strip() for line in file if line.strip()))
        with open("links.txt", "w", encoding="utf-8") as file:
            file.writelines(f"{url}\n" for url in urls)
    except FileNotFoundError:
        logging.error("links.txt file not found.")
        print("Error: links.txt file not found. Please create the file and add URLs.")
        urls = []
    except UnicodeDecodeError as e:
        logging.error(f"Error reading links.txt: {e}")
        print("Error: Unable to read links.txt due to encoding issues. Check error.log for details.")
        urls = []

    try:
        with open("emails.txt", "w", encoding="utf-8") as file:
            file.write("")
    except Exception as e:
        logging.error(f"Error initializing emails.txt: {e}")
        print("Error initializing emails.txt. Check error.log for details.")

    try:
        extract_emails_from_urls(urls, depth=2, output_file="emails.txt")
        print("Emails are being saved in real-time to emails.txt")
    except Exception as e:
        logging.error(f"Unexpected error during email extraction: {e}")
        print("Unexpected error during email extraction. Check error.log for details.")