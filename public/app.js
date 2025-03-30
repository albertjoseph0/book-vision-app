document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const bookList = document.getElementById('bookList');
    const scanBtn = document.getElementById('scanBtn');
    const photoUpload = document.getElementById('photoUpload');
    const searchInput = document.getElementById('searchInput');
    const sortSelect = document.getElementById('sortSelect');
    const statusDiv = document.getElementById('status');
    const loader = document.getElementById('loader');
    const bookCountElement = document.getElementById('bookCount');
    
    // Auth elements
    const signInButton = document.getElementById('signInButton');
    const userProfile = document.getElementById('userProfile');
    const userName = document.getElementById('userName');
    const profilePicture = document.getElementById('profilePicture');
    
    // For modal dialog
    let confirmationModal = null;
    
    // Data store
    let books = [];
    let csrfToken = ''; // Store CSRF token
    
    // Get CSRF token from meta tag
    function getCsrfToken() {
        const metaTag = document.querySelector('meta[name="csrf-token"]');
        if (metaTag) {
            return metaTag.getAttribute('content');
        }
        return '';
    }
    
    // Initialize CSRF token
    csrfToken = getCsrfToken();
    
    // Debug log function
    function logDebug(context, message, data = null) {
        console.log(`[${context}] ${message}`);
        if (data) {
            console.log(data);
        }
    }
    
    // Function to update the book count display
    function updateBookCount(count) {
        bookCountElement.textContent = `${count} Book${count !== 1 ? 's' : ''}`;
        logDebug('BookCount', `Updated book count: ${count}`);
    }
    
    // Event listeners
    scanBtn.addEventListener('click', () => photoUpload.click());
    photoUpload.addEventListener('change', uploadPhoto);
    searchInput.addEventListener('input', filterBooks);
    sortSelect.addEventListener('change', sortBooks);
    
    // Initialize - fetch books and check auth status on page load
    logDebug('Init', 'Application initialized, fetching books and checking auth');
    fetchBooks();
    checkAuthStatus();
    
    // Functions
    async function fetchBooks() {
        logDebug('Books', 'Fetching books from server');
        
        try {
            // Include credentials to ensure cookies are sent
            const response = await fetch('/books', {
                credentials: 'include',
                headers: {
                    'CSRF-Token': csrfToken // Include CSRF token in request
                }
            });
            logDebug('Books', `Fetch response status: ${response.status}`);
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Failed to fetch books: ${response.status} ${errorText}`);
            }
            
            const data = await response.json();
            
            // Update CSRF token if provided in response
            if (data.csrfToken) {
                csrfToken = data.csrfToken;
                logDebug('CSRF', 'Updated CSRF token from books response');
            }
            
            // Handle new response format with books array
            books = data.books || data;
            logDebug('Books', `Received ${books.length} books from server`, books);
            
            renderBooks(books);
            updateBookCount(books.length); // Update the book count
        } catch (error) {
            console.error('Error loading books:', error);
            showStatus('Error loading books: ' + error.message, 'error');
        }
    }
    
    async function uploadPhoto(event) {
        if (!event.target.files || !event.target.files[0]) {
            logDebug('Upload', 'No file selected');
            return;
        }
        
        const photo = event.target.files[0];
        logDebug('Upload', 'Photo selected for upload', {
            name: photo.name,
            type: photo.type,
            size: photo.size
        });
        
        const formData = new FormData();
        formData.append('photo', photo);
        // Add CSRF token to form data
        formData.append('_csrf', csrfToken);
        
        // Show loading state
        loader.style.display = 'block';
        bookList.style.display = 'none';
        statusDiv.textContent = '';
        statusDiv.className = 'status';
        
        logDebug('Upload', 'Uploading photo to server...');
        
        try {
            // Include credentials to ensure cookies are sent
            const response = await fetch('/scan', {
                method: 'POST',
                body: formData,
                credentials: 'include',
                headers: {
                    'CSRF-Token': csrfToken // Also include in headers for extra protection
                }
            });
            
            logDebug('Upload', `Scan response status: ${response.status}`);
            
            const result = await response.json();
            logDebug('Upload', 'Scan result received', result);
            
            // Update CSRF token if provided in response
            if (result.csrfToken) {
                csrfToken = result.csrfToken;
                logDebug('CSRF', 'Updated CSRF token from scan response');
            }
            
            if (!response.ok) {
                throw new Error(result.message || result.error || 'Failed to process image');
            }
            
            // Reload books after successful scan
            logDebug('Upload', 'Scan successful, reloading books');
            await fetchBooks(); // Will update book count through fetchBooks()
            showStatus(`Success! ${result.added || 'New'} books added.`, 'success');
        } catch (error) {
            console.error('Error processing image:', error);
            showStatus(error.message || 'Error processing image', 'error');
        } finally {
            // Reset loader and file input
            loader.style.display = 'none';
            bookList.style.display = 'grid';
            photoUpload.value = '';
            logDebug('Upload', 'Upload process completed');
        }
    }
    
    function filterBooks() {
        const searchTerm = searchInput.value.toLowerCase();
        logDebug('Filter', `Filtering books with term: "${searchTerm}"`);
        
        if (!searchTerm) {
            renderBooks(books);
            return;
        }
        
        const filtered = books.filter(book => 
            book.title.toLowerCase().includes(searchTerm) || 
            book.author.toLowerCase().includes(searchTerm)
        );
        
        logDebug('Filter', `Found ${filtered.length} books matching filter`);
        renderBooks(filtered);
        
        // Note: We don't update the book count here as it should always show total books
    }
    
    function sortBooks() {
        const sortOption = sortSelect.value;
        logDebug('Sort', `Sorting books by: ${sortOption}`);
        
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
                sorted.sort((a, b) => new Date(a.date_added) - new Date(a.date_added));
                break;
        }
        
        renderBooks(sorted);
        
        // Note: We don't update the book count here as it should always show total books
    }
    
    function renderBooks(booksToRender) {
        logDebug('Render', `Rendering ${booksToRender.length} books`);
        bookList.innerHTML = '';
        
        if (booksToRender.length === 0) {
            logDebug('Render', 'No books to display');
            bookList.innerHTML = '<div class="no-books">No books found. Try scanning your bookshelf!</div>';
            return;
        }
        
        booksToRender.forEach(book => {
            const bookCard = document.createElement('div');
            bookCard.className = 'book-card';
            bookCard.dataset.id = book.id; // Store book ID in dataset for deletion
            
            const dateAdded = new Date(book.date_added).toLocaleDateString();
            
            bookCard.innerHTML = `
                <button class="delete-btn" data-id="${book.id}">✕</button>
                <h3 class="book-title">${book.title}</h3>
                <div class="book-author">by ${book.author}</div>
                <div class="book-date">Added on ${dateAdded}</div>
            `;
            
            // Add event listener to the delete button
            const deleteBtn = bookCard.querySelector('.delete-btn');
            deleteBtn.addEventListener('click', (e) => {
                e.stopPropagation(); // Prevent event bubbling
                confirmDeleteBook(book.id, book.title);
            });
            
            bookList.appendChild(bookCard);
        });
    }
    
    function showStatus(message, type) {
        logDebug('Status', `Showing status message: ${message} (${type})`);
        
        statusDiv.textContent = message;
        statusDiv.className = `status ${type}`;
        
        // Auto clear success messages after 5 seconds
        if (type === 'success') {
            setTimeout(() => {
                statusDiv.textContent = '';
                statusDiv.className = 'status';
                logDebug('Status', 'Cleared success message');
            }, 5000);
        }
    }
    
    // Authentication functions - Simplified to use Azure App Service authentication
    async function checkAuthStatus() {
        logDebug('Auth', 'Checking authentication status');
        
        try {
            // Azure Static Web Apps provides /.auth/me endpoint that returns user info 
            const response = await fetch('/.auth/me', {
                credentials: 'include'
            });
            logDebug('Auth', `Auth check response status: ${response.status}`);
            
            const authData = await response.json();
            logDebug('Auth', 'Authentication data received', authData);
            
            // Check if user is authenticated (array has items)
            if (authData && authData.length > 0) {
                // User is authenticated - show profile
                logDebug('Auth', 'User is authenticated');
                displayUserProfile(authData[0]);
            } else {
                // User is not authenticated - show sign in button
                logDebug('Auth', 'User is not authenticated');
                signInButton.style.display = 'flex';
                userProfile.style.display = 'none';
            }
        } catch (error) {
            console.error('Error checking authentication status:', error);
            // If there's an error, default to showing sign in button
            logDebug('Auth', 'Error checking auth status, showing sign in button');
            signInButton.style.display = 'flex';
            userProfile.style.display = 'none';
        }
    }
    
    function displayUserProfile(userData) {
        logDebug('Auth', 'Displaying user profile', userData);
        
        // Hide sign in button and show profile
        signInButton.style.display = 'none';
        userProfile.style.display = 'flex';
        
        // Extract user information directly from Azure's response
        // Azure provides user_claims array with typ/val pairs
        let displayName = null;
        let pictureUrl = null;
        
        if (userData && userData.user_claims) {
            // Find name from standard claims
            const nameClaim = userData.user_claims.find(c => 
                c.typ === 'name' || 
                c.typ === 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'
            );
            
            if (nameClaim) {
                displayName = nameClaim.val;
            }
            
            // Fallback to email or preferred username
            if (!displayName) {
                const emailClaim = userData.user_claims.find(c => 
                    c.typ === 'email' || 
                    c.typ === 'preferred_username' ||
                    c.typ === 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'
                );
                if (emailClaim) {
                    displayName = emailClaim.val;
                }
            }
            
            // Look for picture claim
            const pictureClaim = userData.user_claims.find(c => 
                c.typ === 'picture' || 
                c.typ === 'urn:google:picture'
            );
            if (pictureClaim) {
                pictureUrl = pictureClaim.val;
            }
        }
        
        // Use default if no name found
        if (!displayName) {
            displayName = 'User';
        }
        
        userName.textContent = displayName;
        logDebug('Auth', `User display name set to: ${displayName}`);
        
        // Set profile picture if available
        if (pictureUrl) {
            profilePicture.src = pictureUrl;
            profilePicture.style.display = 'block';
            logDebug('Auth', 'Profile picture set');
        } else {
            // Use a default avatar
            profilePicture.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23bbb"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 3c1.66 0 3 1.34 3 3s-1.34 3-3 3-3-1.34-3-3 1.34-3 3-3zm0 14.2c-2.5 0-4.71-1.28-6-3.22.03-1.99 4-3.08 6-3.08 1.99 0 5.97 1.09 6 3.08-1.29 1.94-3.5 3.22-6 3.22z"/></svg>';
            logDebug('Auth', 'Using default profile picture');
        }
    }
    
    // Book deletion functions
    function confirmDeleteBook(bookId, bookTitle) {
        logDebug('Delete', `Confirming deletion of book: ${bookTitle} (ID: ${bookId})`);
        
        // Create modal if it doesn't exist
        if (!confirmationModal) {
            confirmationModal = document.createElement('div');
            confirmationModal.className = 'modal-overlay';
            document.body.appendChild(confirmationModal);
            logDebug('Delete', 'Created confirmation modal');
        }
        
        // Set modal content
        confirmationModal.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h3>Confirm Deletion</h3>
                </div>
                <div class="modal-body">
                    <p>Are you sure you want to delete "<strong>${bookTitle}</strong>"?</p>
                    <p>This action cannot be undone.</p>
                </div>
                <div class="modal-footer">
                    <button class="btn-cancel">Cancel</button>
                    <button class="btn-confirm">Delete</button>
                </div>
            </div>
        `;
        
        // Show modal
        confirmationModal.style.display = 'flex';
        
        // Add event listeners
        const cancelBtn = confirmationModal.querySelector('.btn-cancel');
        const confirmBtn = confirmationModal.querySelector('.btn-confirm');
        
        cancelBtn.addEventListener('click', closeModal);
        
        confirmBtn.addEventListener('click', () => {
            deleteBook(bookId);
            closeModal();
        });
        
        // Close modal when clicking outside
        confirmationModal.addEventListener('click', (e) => {
            if (e.target === confirmationModal) {
                closeModal();
            }
        });
        
        // Helper function to close modal
        function closeModal() {
            confirmationModal.style.display = 'none';
            logDebug('Delete', 'Closed confirmation modal');
        }
    }
    
    async function deleteBook(bookId) {
        logDebug('Delete', `Deleting book with ID: ${bookId}`);
        
        try {
            // Include credentials to ensure cookies are sent
            const response = await fetch(`/books/${bookId}`, {
                method: 'DELETE',
                credentials: 'include',
                headers: {
                    'CSRF-Token': csrfToken // Include CSRF token in the request
                }
            });
            
            logDebug('Delete', `Delete response status: ${response.status}`);
            
            const responseData = await response.json();
            
            // Update CSRF token if provided in response
            if (responseData.csrfToken) {
                csrfToken = responseData.csrfToken;
                logDebug('CSRF', 'Updated CSRF token from delete response');
            }
            
            if (!response.ok) {
                throw new Error(responseData.message || responseData.error || 'Failed to delete book');
            }
            
            // Remove book from data store
            books = books.filter(book => book.id !== bookId);
            logDebug('Delete', `Book removed from data store, ${books.length} books remaining`);
            
            // Update book count
            updateBookCount(books.length);
            
            // Remove book card from UI
            const bookCard = document.querySelector(`.book-card[data-id="${bookId}"]`);
            if (bookCard) {
                bookCard.remove();
                logDebug('Delete', 'Book card removed from UI');
            }
            
            // Show success message
            showStatus('Book deleted successfully', 'success');
            
            // If no books left, show the "no books" message
            if (books.length === 0) {
                logDebug('Delete', 'No books remaining, showing "no books" message');
                bookList.innerHTML = '<div class="no-books">No books found. Try scanning your bookshelf!</div>';
            }
            
        } catch (error) {
            console.error('Error deleting book:', error);
            showStatus(error.message || 'Error deleting book', 'error');
        }
    }
    
    // CSRF token refresh function
    async function refreshCsrfToken() {
        try {
            const response = await fetch('/csrf-token', {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.csrfToken) {
                    csrfToken = data.csrfToken;
                    logDebug('CSRF', 'Successfully refreshed CSRF token');
                    return true;
                }
            }
            
            logDebug('CSRF', 'Failed to refresh CSRF token');
            return false;
        } catch (error) {
            console.error('Error refreshing CSRF token:', error);
            return false;
        }
    }
    
    // Add diagnostic function - accessible from browser console
    window.runDiagnostics = async function() {
        logDebug('Diagnostics', 'Running diagnostics');
        
        try {
            // Check authentication status
            console.log('%c👤 Authentication Status Check', 'font-size: 14px; font-weight: bold; color: #704214;');
            const authResponse = await fetch('/api/auth-status', {
                credentials: 'include',
                headers: {
                    'CSRF-Token': csrfToken
                }
            });
            const authStatus = await authResponse.json();
            
            // Update CSRF token if provided
            if (authStatus.csrfToken) {
                csrfToken = authStatus.csrfToken;
                logDebug('CSRF', 'Updated CSRF token from auth status response');
            }
            
            console.log(authStatus);
            
            // Check Azure's built-in auth endpoint
            console.log('%c🔐 Azure Auth Endpoint', 'font-size: 14px; font-weight: bold; color: #704214;');
            const azureAuthResponse = await fetch('/.auth/me', {
                credentials: 'include'
            });
            const azureAuthData = await azureAuthResponse.json();
            console.log(azureAuthData);
            
            // Check database connection and schema
            console.log('%c📊 Book Vision App Diagnostics', 'font-size: 16px; font-weight: bold; color: #704214;');
            const response = await fetch('/api/diagnostics', {
                credentials: 'include',
                headers: {
                    'CSRF-Token': csrfToken
                }
            });
            const diagnosticData = await response.json();
            
            // Update CSRF token if provided
            if (diagnosticData.csrfToken) {
                csrfToken = diagnosticData.csrfToken;
                logDebug('CSRF', 'Updated CSRF token from diagnostics response');
            }
            
            console.log(diagnosticData);
            
            return {
                authStatus: authStatus,
                azureAuth: azureAuthData,
                diagnostics: diagnosticData,
                clientState: {
                    books: books,
                    bookCount: books.length,
                    csrfToken: csrfToken ? 'Present (hidden)' : 'Missing',
                    elements: {
                        bookListEmpty: !bookList.children.length,
                        statusVisible: !!statusDiv.textContent,
                        loaderVisible: loader.style.display !== 'none'
                    }
                }
            };
        } catch (error) {
            console.error('Diagnostics failed:', error);
            return { error: error.message };
        }
    };
    
    // Add auth refresh function - can be used for troubleshooting
    window.refreshAuth = async function() {
        logDebug('Auth', 'Manually refreshing authentication');
        await checkAuthStatus();
        return 'Authentication refresh completed';
    };
    
    // Add CSRF token refresh function - can be used for troubleshooting
    window.refreshCsrf = async function() {
        logDebug('CSRF', 'Manually refreshing CSRF token');
        const success = await refreshCsrfToken();
        return success ? 'CSRF token refresh completed' : 'CSRF token refresh failed';
    };
    
    console.log('Book Vision App initialized. For troubleshooting:');
    console.log('- Run window.runDiagnostics() for detailed diagnostic info');
    console.log('- Run window.refreshAuth() to refresh authentication state');
    console.log('- Run window.refreshCsrf() to refresh CSRF token');
});