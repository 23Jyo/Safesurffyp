// JavaScript for SafeSurf Search functionality

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search-input');
    const searchBtn = document.getElementById('search-btn');

    // Placeholder: Example function to simulate search
    const performSearch = (query) => {
        if (query.trim() === '') {
            alert('Please enter a search term.');
            return;
        }
        alert(`Searching for: ${query}`);
    };

    // Add click event to the search button
    searchBtn.addEventListener('click', () => {
        const query = searchInput.value;
        performSearch(query);
    });

    // Allow Enter key to trigger search
    searchInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            const query = searchInput.value;
            performSearch(query);
        }
    });
});
