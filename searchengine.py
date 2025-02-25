from flask import Flask, render_template, request, render_template_string
from bs4 import BeautifulSoup
import requests
import sqlite3
from model_runner import run_phishing_model
import re

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

def is_valid_url(query):
    """Check if the input is a valid URL."""
    url_pattern = re.compile(
        r'^(https?|ftp):\/\/'  # Protocol (http, https, ftp)
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,6}'  # Domain name
        r'localhost|'  # Localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IPv4 Address
        r'(:\d+)?(\/[^\s]*)?$'  # Port and optional path/query parameters
    )
    return bool(url_pattern.match(query)) or "." in query


@app.route('/search', methods=['POST'])
def search():
    """Perform the search and return results."""
    query = request.form.get('query')
    
    if not query:
        return render_template('home.html', error="Please enter a search query.")

    print(f"User Input: {query}")
    
    if is_valid_url(query):
        print("✅ Detected as URL, running phishing model...")  # Debugging
        # It's a URL → Check if it's malicious
        model_output = run_phishing_model(query)
        if int(model_output.strip()) == 1:
            status = "Website is safe to use."
            button = f'<a href="{query}" target="_blank" class="btn btn-success">Continue</a>'
        else:
            status = "Website is unsafe to use."
            button = f'<a href="{query}" target="_blank" class="btn btn-danger">Still want to continue?</a>'

        return render_template('check_url.html', link=query, status=status, button=button, model_output=model_output)
    else:
        print("🔍 Detected as search query, performing web scraping...")  # Debugging

        query = query.replace(' ', '+')
        url = f"https://www.bing.com/search?q={query}"
        image_url = f"https://www.bing.com/images/search?q={query}"# Use Google Images search
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        results = []
        unique_urls = set()
        
        # Extract text results (standard search page)
        for link in soup.select('li.b_algo h2 a, h2 a'):
            href = link.get('href')
            
            if 'http' in href and href not in unique_urls:
                try:
                    # Fetch metadata from the linked page
                    page_response = requests.get(href, headers=headers, timeout=5)
                    page_soup = BeautifulSoup(page_response.text, 'html.parser')

                    # Extract metadata
                    tags = {
                        'description': page_soup.find('meta', {'name': 'description'}).get('content', '') if page_soup.find('meta', {'name': 'description'}) else '',
                        'keywords': page_soup.find('meta', {'name': 'keywords'}).get('content', '') if page_soup.find('meta', {'name': 'keywords'}) else '',
                        'author': page_soup.find('meta', {'name': 'author'}).get('content', '') if page_soup.find('meta', {'name': 'author'}) else ''
                    }
                except Exception as e:
                    # Fallback metadata if page fetching fails
                    tags = {'description': link.text.strip(), 'keywords': '', 'author': ''}

                # Calculate rating
                rating = calculate_metadata_rating(tags)
                results.append({'url': href, 'description': tags['description'], 'rating': rating})
                unique_urls.add(href)
                
         #scrape images separately from Bing images       
        img_response = requests.get(image_url, headers=headers)
        img_soup = BeautifulSoup(img_response.text, 'html.parser')

        images = []
        unique_images = set()

        # Extract images (Google Images search)
        for img_tag in img_soup.find_all('img'):
            img_src = img_tag.get('data-src') or img_tag.get('src')
            if img_src and img_src.startswith("http") and img_src not in unique_images:
                images.append(img_src)
                unique_images.add(img_src)

        return render_template('results.html', query=query, results=results, images=images)
    return render_template('home.html')

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

        # Save the link to a file
        with open("input_url.txt", "w") as file:
            file.write(link)

        # Run the phishing detection model
        model_output = run_phishing_model(link)

        # Determine website safety
        if int(model_output.strip()) == 1:  # Ensure it's interpreted as an integer
            status = "Website is safe to use."
            button = f'<a href="{link}" target="_blank" class="btn btn-success">Continue</a>'
        else:
            status = "Website is unsafe to use."
            button = f'<a href="{link}" target="_blank" class="btn btn-danger">Still want to continue?</a>'


        # Render HTML directly
         # Use an HTML template instead of inline HTML
        return render_template('check_url.html', link=link, status=status, button=button, model_output=model_output)

    return "No link provided."


if __name__ == '__main__':
    init_db()
    app.run(debug=True)


