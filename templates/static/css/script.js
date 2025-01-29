document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-input');
    const searchBtn = document.getElementById('search-btn');
    const resultsContainer = document.getElementById('results-container'); // Make sure this div exists in your HTML

    // Function to fetch search results
    const performSearch = (query) => {
        if (query.trim() === '') {
            alert('Please enter a search term.');
            return;
        }

        // Show loading message
        resultsContainer.innerHTML = '<p>Searching...</p>';

        fetch(`/search?query=${encodeURIComponent(query)}`)
            .then(response => response.json())
            .then(data => {
                displayResults(data.results);
            })
            .catch(error => {
                console.error("Error fetching search results:", error);
                resultsContainer.innerHTML = '<p>Error fetching results. Please try again.</p>';
            });
    };

    // Function to display search results
    const displayResults = (results) => {
        resultsContainer.innerHTML = ''; // Clear previous results

        if (results.length === 0) {
            resultsContainer.innerHTML = '<p>No results found.</p>';
            return;
        }

        results.forEach(result => {
            const resultItem = document.createElement('div');
            resultItem.classList.add('result-item');

            const link = document.createElement('a');
            link.href = result.url;
            link.target = '_blank';
            link.innerText = result.url;
            link.classList.add('result-url');

            const description = document.createElement('p');
            description.innerText = result.description;
            description.classList.add('result-description');

            const safetyStatus = document.createElement('p');
            safetyStatus.innerText = 'Checking safety...';
            safetyStatus.classList.add('result-safety');

            // Check URL safety
            checkPhishing(result.url, safetyStatus);

            resultItem.appendChild(link);
            resultItem.appendChild(description);
            resultItem.appendChild(safetyStatus);
            resultsContainer.appendChild(resultItem);
        });
    };

    // Function to check phishing status
    const checkPhishing = (url, statusElement) => {
        fetch(`/data1?link=${encodeURIComponent(url)}`)
            .then(response => response.json())
            .then(data => {
                console.log("Phishing check data:", data);
                statusElement.innerText = data.prediction === 1 ? '✅ Safe to Use' : '❌ Unsafe!';
                statusElement.style.color = data.prediction === 1 ? 'green' : 'red';
            })
            .catch(error => {
                console.error("Error checking phishing status:", error);
                statusElement.innerText = '⚠️ Error checking safety';
                statusElement.style.color = 'orange';
            });
    };

    // Add event listeners
    searchBtn.addEventListener('click', () => performSearch(searchInput.value));
    searchInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') performSearch(searchInput.value);
    });
});

