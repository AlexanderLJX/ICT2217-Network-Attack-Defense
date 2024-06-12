import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def clone_website(url, save_dir):
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Save the main page
    with open(os.path.join(save_dir, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(response.text)

    # Download linked resources (CSS, JS, images)
    resources = []
    for tag in soup.find_all(['link', 'script', 'img']):
        src = tag.get('href') or tag.get('src')
        if src:
            src_url = urljoin(url, src)
            resources.append(src_url)
            # Determine file path to save
            resource_path = os.path.join(save_dir, os.path.basename(urlparse(src_url).path))
            # Fetch and save resource
            try:
                res = requests.get(src_url)
                with open(resource_path, 'wb') as res_file:
                    res_file.write(res.content)
                print(f"Downloaded: {src_url}")
            except requests.RequestException as e:
                print(f"Failed to download {src_url}: {e}")

    print("Website cloning completed.")

# Example usage
clone_website('https://www.google.com', 'cloned_site')
