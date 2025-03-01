from flask import Flask, render_template, request, render_template_string
from bs4 import BeautifulSoup
import requests
import sqlite3
from model_runner import run_phishing_model

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('search.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY, url TEXT, description TEXT, rating INTEGER)''')
    conn.commit()
    conn.close()

# Metadata-based rating calculation
def calculate_metadata_rating(tags):
    """Calculate a rating based on metadata tags and other attributes."""
    rating = 0

    # Description tag
    if 'description' in tags and tags['description']:
        rating += 2
        if len(tags['description']) > 50:
            rating += 1  # Additional points for longer descriptions

    # Keywords tag
    if 'keywords' in tags and tags['keywords']:
        rating += 2
        relevant_keywords = [
            'official', 'verified', 'trusted', 'guide', 'latest', 'high-quality',
            'recommended', 'analysis', 'study', 'review', 'current', '2024', 'secure',
            'certified', 'tutorial', 'expert', 'support'
        ]
        if any(keyword.lower() in tags['keywords'].lower() for keyword in relevant_keywords):
            rating += 1

    # Author tag
    if 'author' in tags and tags['author']:
        rating += 1

    # Normalize rating to a scale of 1-5
    return min(max(rating, 1), 5)

@app.route('/')
def home():
    """Render the homepage."""
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

import re  # Import regex module

@app.route('/search', methods=['POST'])
def search():
    """Perform the search or check a URL if it's directly entered."""
    query = request.form.get('query')

    if query:
        # Check if the input is a URL
        url_pattern = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # Domain name
            r'localhost|'  # Allow localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
            r'(?::\d+)?'  # Optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )

        if re.match(url_pattern, query):  # If the input is a valid URL
            return check_url_directly(query)  # Call phishing detection directly
        else:
            return process_search_query(query)  # Perform normal search

    return render_template('home.html')


def check_url_directly(url):
    """Runs phishing detection on a direct URL input and returns results."""
    print(f"🔍 Direct URL check triggered for: {url}")
    
    # Run phishing model
    model_output = run_phishing_model(url)

    try:
        prediction = int(model_output.strip())
        if prediction == 1:
            status = "✅ Website is safe to use."
            button = f'<a href="{url}" target="_blank" class="btn btn-success">Continue</a>'
        else:
            status = "❌ Website is unsafe to use."
            button = f'<a href="{url}" target="_blank" class="btn btn-danger">Still want to continue?</a>'
    except (ValueError, AttributeError):
        status = "⚠️ Unable to verify website safety."
        button = f'<a href="{url}" target="_blank" class="btn btn-warning">Proceed with caution</a>'

    return render_template('check_url.html', link=url, status=status, button=button, model_output=model_output)


def process_search_query(query):
    """Handles normal search queries using web scraping."""
    query = query.replace(' ', '+')
    url = f"https://www.bing.com/search?q={query}"
    image_url = f"https://www.bing.com/images/search?q={query}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, 'html.parser')

    results = []
    unique_urls = set()
    
    for link in soup.select('li.b_algo h2 a, h2 a'):
        href = link.get('href')

        if 'http' in href and href not in unique_urls:
            try:
                page_response = requests.get(href, headers=headers, timeout=5)
                page_soup = BeautifulSoup(page_response.text, 'html.parser')

                tags = {
                    'description': page_soup.find('meta', {'name': 'description'}).get('content', '') if page_soup.find('meta', {'name': 'description'}) else '',
                    'keywords': page_soup.find('meta', {'name': 'keywords'}).get('content', '') if page_soup.find('meta', {'name': 'keywords'}) else '',
                    'author': page_soup.find('meta', {'name': 'author'}).get('content', '') if page_soup.find('meta', {'name': 'author'}) else ''
                }
            except Exception as e:
                tags = {'description': link.text.strip(), 'keywords': '', 'author': ''}

            rating = calculate_metadata_rating(tags)
            results.append({'url': href, 'description': tags['description'], 'rating': rating})
            unique_urls.add(href)

    # Scraping images separately from Bing Images       
    img_response = requests.get(image_url, headers=headers)
    img_soup = BeautifulSoup(img_response.text, 'html.parser')

    images = []
    unique_images = set()

    for img_tag in img_soup.find_all('img'):
        img_src = img_tag.get('data-src') or img_tag.get('src')
        if img_src and img_src.startswith("http") and img_src not in unique_images:
            images.append(img_src)
            unique_images.add(img_src)

    return render_template('results.html', query=query, results=results, images=images)


@app.route('/data1')
def check_url():
    """Check if a URL is malicious using the phishing detection model."""
    print("🔍 /data1 route triggered!")
    link = request.args.get('link', '')
    print(f"🔍 /data1 route triggered with link: {link}")

    if link:
        # Remove "/url?q=" if present
        if link.startswith("/url?q="):
            try:
                link = link.split("/url?q=")[1].split("&")[0]
            except IndexError:
                return "Invalid URL format"

        # Run the phishing detection model
        model_output = run_phishing_model(link)
        
        # Handle the model output with better error checking
        try:
            # Try to convert the output to an integer
            prediction = int(model_output.strip())
            if prediction == 1:
                status = "Website is safe to use."
                button = f'<a href="{link}" target="_blank" class="btn btn-success">Continue</a>'
            else:
                status = "Website is unsafe to use."
                button = f'<a href="{link}" target="_blank" class="btn btn-danger">Still want to continue?</a>'
        except (ValueError, AttributeError):
            # If conversion fails, treat as unsafe
            status = "Unable to verify website safety."
            button = f'<a href="{link}" target="_blank" class="btn btn-warning">Proceed with caution</a>'

        return render_template('check_url.html', link=link, status=status, button=button, model_output=model_output)

    return "No link provided."


if __name__ == '__main__':
    init_db()
    app.run(debug=True)


