from flask import Flask, render_template, request
from bs4 import BeautifulSoup
import requests
import sqlite3

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

@app.route('/search', methods=['POST'])
def search():
    """Perform the search and return results."""
    query = request.form.get('query')
    if query:
        query = query.replace(' ', '+')
        url = f"https://www.google.com/search?q={query}&tbm=isch"  # Use Google Images search
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        results = []
        images = []
        
        # Extract text results (standard search page)
        for link in soup.select('a'):
            href = link.get('href')
            
            
            if 'http' in href:
                try:
                    # Fetch metadata from the linked page
                    page_response = requests.get(href, headers=headers, timeout=5)
                    page_soup = BeautifulSoup(page_response.text, 'html.parser')

                    # Extract metadata
                    tags = {
                        'description': page_soup.find('meta', {'name': 'description'})['content'] if page_soup.find('meta', {'name': 'description'}) else '',
                        'keywords': page_soup.find('meta', {'name': 'keywords'})['content'] if page_soup.find('meta', {'name': 'keywords'}) else '',
                        'author': page_soup.find('meta', {'name': 'author'})['content'] if page_soup.find('meta', {'name': 'author'}) else ''
                    }
                except Exception as e:
                    # Fallback metadata if page fetching fails
                    tags = {'description': link.text.strip(), 'keywords': '', 'author': ''}

                # Calculate rating
                rating = calculate_metadata_rating(tags)
                results.append({'url': href, 'description': tags['description'], 'rating': rating})

        # Extract images (Google Images search)
        for img_tag in soup.find_all('img'):
            img_src = img_tag.get('data-src') or img_tag.get('src')
            if img_src and not img_src.startswith('data:'):  # Ignore base64-encoded images
                if img_src.startswith('/'):  # Convert relative URL to absolute
                    img_src = f"https://www.google.com{img_src}"
                images.append(img_src)

        return render_template('results.html', query=query, results=results, images=images)
    return render_template('home.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)


