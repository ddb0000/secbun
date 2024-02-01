"""
Asynchronous Web Scraper

Usage:
    - Basic Scrape:
      python scraper.py <url> --element <element> --attribute <attribute> --value <value>

    - JSON Output:
      python scraper.py <url> --element <element> --attribute <attribute> --value <value> --json

Options:
    -h, --help           Show this help message and exit.
    --element <element>  HTML element to search for.
    --attribute <attr>   Attribute of the element to refine the search.
    --value <value>      Value of the attribute to refine the search.
    --json               Output results in JSON format.

Example:
    python scraper.py http://example.com --element div --attribute class --value header --json
"""
import asyncio
import requests
import logging
import json
import argparse
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO, format='%(message)s')

async def fetch_content(url):
    """
    Fetch the content of a webpage.

    Args:
        url (str): URL of the webpage to scrape.

    Returns:
        str: HTML content of the page.
    """
    loop = asyncio.get_event_loop()
    content = await loop.run_in_executor(None, requests.get, url)
    return content.text if content.status_code == 200 else None

async def parse_content(html, element, attribute=None, value=None):
    """
    Parse the HTML content and extract elements based on criteria.

    Args:
        html (str): HTML content.
        element (str): HTML element to search for.
        attribute (str, optional): Attribute of the element to refine the search.
        value (str, optional): Value of the attribute to refine the search.

    Returns:
        list: Extracted elements.
    """
    soup = BeautifulSoup(html, 'html.parser')
    if attribute and value:
        elements = soup.findAll(element, {attribute: value})
    else:
        elements = soup.findAll(element)
    return elements

def display(elements):
    """
    Display the extracted elements.

    Args:
        elements (list): Extracted elements.
    """
    for element in elements:
        print(element.get_text())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Asynchronous Web Scraper")
    parser.add_argument("url", type=str, help="URL to scrape")
    parser.add_argument("--element", type=str, required=True, help="HTML element to search for")
    parser.add_argument("--attribute", type=str, help="Attribute of the element to refine the search")
    parser.add_argument("--value", type=str, help="Value of the attribute to refine the search")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    # Run the scraping tasks
    loop = asyncio.get_event_loop()
    html_content = loop.run_until_complete(fetch_content(args.url))
    if html_content:
        elements = loop.run_until_complete(parse_content(html_content, args.element, args.attribute, args.value))
        
        if args.json:
            # Output in JSON format
            print(json.dumps([element.get_text() for element in elements], indent=2))
        else:
            # Plain text output
            display(elements)
    else:
        logging.error("Failed to retrieve content.")
