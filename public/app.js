document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const bookList = document.getElementById('bookList');
    const scanBtn = document.getElementById('scanBtn');
    const photoUpload = document.getElementById('photoUpload');
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    const statusDiv = document.getElementById('status');
    const loader = document.getElementById('loader');
    
    // Data store
    let books = [];
    
    // Event listeners
    scanBtn.addEventListener('click', () => photoUpload.click());
    photoUpload.addEventListener('change', uploadPhoto);
    searchInput.addEventListener('input', filterBooks);
    sortSelect.addEventListener('change', sortBooks);
    
    // Initialize - fetch books on page load
    fetchBooks();
    
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
});