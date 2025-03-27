document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const bookList = document.getElementById('bookList');
    const scanBtn = document.getElementById('scanBtn');
    const photoUpload = document.getElementById('photoUpload');
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    const statusDiv = document.getElementById('status');
    const loader = document.getElementById('loader');
    
    // Auth elements
    const signInButton = document.getElementById('signInButton');
    const userProfile = document.getElementById('userProfile');
    const userName = document.getElementById('userName');
    const profilePicture = document.getElementById('profilePicture');
    
    // Data store
    let books = [];
    
    // Event listeners
    scanBtn.addEventListener('click', () => photoUpload.click());
    photoUpload.addEventListener('change', uploadPhoto);
    searchInput.addEventListener('input', filterBooks);
    sortSelect.addEventListener('change', sortBooks);
    
    // Initialize - fetch books and check auth status on page load
    fetchBooks();
    checkAuthStatus();
    
    // Functions
    async function fetchBooks() {
        try {
            const response = await fetch('/books');
            if (!response.ok) throw new Error('Failed to fetch books');
            
            books = await response.json();
            renderBooks(books);
        } catch (error) {
            showStatus('Error loading books', 'error');
            console.error(error);
        }
    }
    
    async function uploadPhoto(event) {
        if (!event.target.files || !event.target.files[0]) return;
        
        const photo = event.target.files[0];
        const formData = new FormData();
        formData.append('photo', photo);
        
        // Show loading state
        loader.style.display = 'block';
        bookList.style.display = 'none';
        statusDiv.textContent = '';
        statusDiv.className = 'status';
        
        try {
            const response = await fetch('/scan', {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (!response.ok) throw new Error(result.message || 'Failed to process image');
            
            // Reload books after successful scan
            await fetchBooks();
            showStatus(`Success! ${result.added || 'New'} books added.`, 'success');
        } catch (error) {
            showStatus(error.message || 'Error processing image', 'error');
            console.error(error);
        } finally {
            // Reset loader and file input
            loader.style.display = 'none';
            bookList.style.display = 'grid';
            photoUpload.value = '';
        }
    }
    
    function filterBooks() {
        const searchTerm = searchInput.value.toLowerCase();
        
        if (!searchTerm) {
            renderBooks(books);
            return;
        }
        
        const filtered = books.filter(book => 
            book.title.toLowerCase().includes(searchTerm) || 
            book.author.toLowerCase().includes(searchTerm)
        );
        
        renderBooks(filtered);
    }
    
    function sortBooks() {
        const sortOption = sortSelect.value;
        let sorted = [...books];
        
        switch (sortOption) {
            case 'title-asc':
                sorted.sort((a, b) => a.title.localeCompare(b.title));
                break;
            case 'title-desc':
                sorted.sort((a, b) => b.title.localeCompare(a.title));
                break;
            case 'author-asc':
                sorted.sort((a, b) => a.author.localeCompare(b.author));
                break;
            case 'author-desc':
                sorted.sort((a, b) => b.author.localeCompare(a.author));
                break;
            case 'date-desc':
                sorted.sort((a, b) => new Date(b.date_added) - new Date(a.date_added));
                break;
            case 'date-asc':
                sorted.sort((a, b) => new Date(a.date_added) - new Date(b.date_added));
                break;
        }
        
        renderBooks(sorted);
    }
    
    function renderBooks(booksToRender) {
        bookList.innerHTML = '';
        
        if (booksToRender.length === 0) {
            bookList.innerHTML = '<div class="no-books">No books found. Try scanning your bookshelf!</div>';
            return;
        }
        
        booksToRender.forEach(book => {
            const bookCard = document.createElement('div');
            bookCard.className = 'book-card';
            
            const dateAdded = new Date(book.date_added).toLocaleDateString();
            
            bookCard.innerHTML = `
                <h3 class="book-title">${book.title}</h3>
                <div class="book-author">by ${book.author}</div>
                <div class="book-date">Added on ${dateAdded}</div>
            `;
            
            bookList.appendChild(bookCard);
        });
    }
    
    function showStatus(message, type) {
        statusDiv.textContent = message;
        statusDiv.className = `status ${type}`;
        
        // Auto clear success messages after 5 seconds
        if (type === 'success') {
            setTimeout(() => {
                statusDiv.textContent = '';
                statusDiv.className = 'status';
            }, 5000);
        }
    }
    
    // Authentication functions
    async function checkAuthStatus() {
        try {
            const response = await fetch('/.auth/me');
            const authData = await response.json();
            
            // Check if user is authenticated (array has items)
            if (authData && authData.length > 0) {
                // User is authenticated - show profile
                displayUserProfile(authData[0]);
            } else {
                // User is not authenticated - show sign in button
                signInButton.style.display = 'flex';
                userProfile.style.display = 'none';
            }
        } catch (error) {
            console.error('Error checking authentication status:', error);
            // If there's an error, default to showing sign in button
            signInButton.style.display = 'flex';
            userProfile.style.display = 'none';
        }
    }
    
    function displayUserProfile(userData) {
        // Hide sign in button and show profile
        signInButton.style.display = 'none';
        userProfile.style.display = 'flex';
        
        // Extract user info - properties depend on the provider (Google in this case)
        // For Google, typical properties include: name, user_id, id_token, provider_name, user_claims
        
        // Set user name - look for various possible claim types
        let displayName = findUserClaim(userData, 'name');
        if (!displayName) {
            // Fallbacks
            displayName = findUserClaim(userData, 'given_name') || 
                          findUserClaim(userData, 'email') || 
                          'User';
        }
        
        userName.textContent = displayName;
        
        // Try to get profile picture (if available)
        const pictureUrl = findUserClaim(userData, 'picture');
        if (pictureUrl) {
            profilePicture.src = pictureUrl;
            profilePicture.style.display = 'block';
        } else {
            // Use a default avatar or hide the image
            profilePicture.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23bbb"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/></svg>';
        }
    }
    
    // Helper function to find a specific claim in the user data
    function findUserClaim(userData, claimType) {
        if (!userData || !userData.user_claims) return null;
        
        const claim = userData.user_claims.find(claim => 
            claim.typ === claimType || 
            claim.type === claimType
        );
        
        return claim ? claim.val : null;
    }
});