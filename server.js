require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sql = require('mssql');
const axios = require('axios');
const path = require('path');
// Add jsonwebtoken for decoding JWT tokens
const jwt = require('jsonwebtoken');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure multer for file uploads
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// Authentication middleware
const extractUserIdentity = (req, res, next) => {
    try {
        // Get the Google ID token from request headers
        const googleIdToken = req.headers['x-ms-token-google-id-token'];
        
        if (googleIdToken) {
            // Decode the JWT token (without verification for now)
            // In production, you should verify the token signature
            const decodedToken = jwt.decode(googleIdToken);
            
            if (decodedToken) {
                // Extract user information from token
                req.user = {
                    id: decodedToken.sub, // Google's unique user ID
                    email: decodedToken.email,
                    name: decodedToken.name,
                    isAuthenticated: true
                };
                
                // Log the extracted user info (for debugging)
                console.log('Authenticated user:', req.user);
            }
        } else {
            // Set a default user object for unauthenticated requests
            req.user = {
                id: 'anonymous',
                isAuthenticated: false
            };
            
            // Log unauthenticated request (for debugging)
            console.log('Unauthenticated request');
        }
    } catch (error) {
        console.error('Error extracting user identity:', error);
        // Set default user for error cases
        req.user = {
            id: 'anonymous',
            isAuthenticated: false
        };
    }
    
    // Always continue to the next middleware
    next();
};

// Apply the authentication middleware to all routes
app.use(extractUserIdentity);

// Set landing page as the default route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// Route for the main app after clicking 'Get Started' or any CTA button
app.get('/app', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve static files - moved after route definitions
app.use(express.static(path.join(__dirname, 'public')));

// Database configuration
const dbConfig = {
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    options: {
        encrypt: true, // Required for Azure SQL
        trustServerCertificate: false
    }
};

// OpenAI API configuration
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

// Connect to database and return a pool
async function getDbPool() {
    try {
        return await sql.connect(dbConfig);
    } catch (err) {
        console.error('Database connection error:', err);
        throw new Error('Failed to connect to database');
    }
}

// Helper function to parse OpenAI Vision API response
function parseVisionResponse(responseData) {
    try {
        // Make sure we have a response with content
        if (!responseData?.choices?.[0]?.message?.content) {
            console.error('Invalid response format from Vision API');
            return [];
        }
        
        // Extract the content from the response
        const content = responseData.choices[0].message.content;
        
        // Since we requested JSON format, try to parse the content as JSON
        let books = [];
        
        try {
            // Parse the JSON string from the content
            const parsedContent = JSON.parse(content);
            
            // Check if the response contains a books array
            if (Array.isArray(parsedContent.books)) {
                books = parsedContent.books;
            } 
            // Or if the response itself is an array
            else if (Array.isArray(parsedContent)) {
                books = parsedContent;
            }
            
            // Filter to ensure each book has both title and author
            books = books.filter(book => 
                book && 
                typeof book === 'object' && 
                typeof book.title === 'string' && 
                typeof book.author === 'string' &&
                book.title.trim() !== '' && 
                book.author.trim() !== ''
            );
            
            // Standardize the format to ensure only title and author are included
            books = books.map(book => ({
                title: book.title.trim(),
                author: book.author.trim()
            }));
            
            // Remove duplicates
            const uniqueBooks = [];
            const seen = new Set();
            
            for (const book of books) {
                const key = `${book.title.toLowerCase()}|${book.author.toLowerCase()}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    uniqueBooks.push(book);
                }
            }
            
            return uniqueBooks;
            
        } catch (jsonError) {
            console.error('Failed to parse JSON from Vision API response:', jsonError);
            console.log('Raw content received:', content);
            // Return empty array if JSON parsing fails
            return [];
        }
    } catch (error) {
        console.error('Error parsing Vision API response:', error);
        return [];
    }
}

// API Routes

// Get all books - UPDATED to only show user's own books or anonymous books
app.get('/books', async (req, res) => {
    try {
        const pool = await getDbPool();
        let query = '';
        let request = pool.request();
        
        // Check if user is authenticated
        if (req.user && req.user.isAuthenticated) {
            // Filter books to show ONLY books that belong to this user
            query = `
                SELECT id, title, author, date_added 
                FROM books 
                WHERE user_id = @userId
                ORDER BY date_added DESC
            `;
            request.input('userId', sql.NVarChar, req.user.id);
            
            console.log(`Fetching books for authenticated user: ${req.user.id}`);
        } else {
            // When not authenticated, only show anonymous books
            query = `
                SELECT id, title, author, date_added 
                FROM books 
                WHERE user_id = 'anonymous'
                ORDER BY date_added DESC
            `;
            
            console.log('Fetching only anonymous books (unauthenticated request)');
        }
        
        const result = await request.query(query);
        res.json(result.recordset);
        
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).json({ message: 'Error fetching books' });
    }
});

// Delete a book (secure version)
app.delete('/books/:id', async (req, res) => {
    const bookId = req.params.id;
    
    if (!bookId) {
        return res.status(400).json({ message: 'Book ID is required' });
    }
    
    try {
        const pool = await getDbPool();
        
        // Get user_id from auth middleware
        const userId = req.user && req.user.isAuthenticated ? req.user.id : 'anonymous';
        
        // Delete the book only if it belongs to this user
        const deleteResult = await pool.request()
            .input('id', sql.Int, bookId)
            .input('userId', sql.NVarChar, userId)
            .query('DELETE FROM books WHERE id = @id AND user_id = @userId');
        
        // Check if any rows were affected
        if (deleteResult.rowsAffected[0] === 0) {
            return res.status(403).json({ 
                message: 'Book not found or you do not have permission to delete it'
            });
        }
        
        res.status(200).json({ message: 'Book deleted successfully' });
        
    } catch (error) {
        console.error('Error deleting book:', error);
        res.status(500).json({ message: 'Error deleting book' });
    }
});

// Scan and process bookshelf photo
app.post('/scan', upload.single('photo'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No photo uploaded' });
    }
    
    try {
        // Convert image buffer to base64
        const base64Image = req.file.buffer.toString('base64');
        
        // Call OpenAI Vision API
        const response = await axios.post(OPENAI_API_URL, {
            model: "gpt-4o", // Use the latest vision model
            messages: [
                {
                    role: "user",
                    content: [
                        {
                            type: "text",
                            text: "Identify all books visible in this image. Return the result as a JSON array of objects, where each object contains ONLY 'title' and 'author' properties. Example format: [{\"title\": \"The Great Gatsby\", \"author\": \"F. Scott Fitzgerald\"}]. Only include books you can clearly see and identify."
                        },
                        {
                            type: "image_url",
                            image_url: {
                                url: `data:image/jpeg;base64,${base64Image}`
                            }
                        }
                    ]
                }
            ],
            max_tokens: 1000,
            response_format: { type: "json_object" }
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            }
        });
        
        // Parse the response to extract book information
        const books = parseVisionResponse(response.data);
        
        if (books.length === 0) {
            return res.status(200).json({ message: 'No books detected in the image', added: 0 });
        }
        
        // Add books to database (avoiding duplicates)
        const pool = await getDbPool();
        let added = 0;
        
        // Get user_id for this request (use 'anonymous' if not authenticated)
        const userId = req.user && req.user.isAuthenticated ? req.user.id : 'anonymous';
        
        for (const book of books) {
            // Skip invalid books (extra safety check)
            if (!book.title || !book.author) {
                continue;
            }
            
            // Check if book already exists for this user
            const existsResult = await pool.request()
                .input('title', sql.NVarChar, book.title)
                .input('author', sql.NVarChar, book.author)
                .input('userId', sql.NVarChar, userId)
                .query('SELECT COUNT(*) as count FROM books WHERE title = @title AND author = @author AND user_id = @userId');
            
            // If book doesn't exist for this user, add it
            if (existsResult.recordset[0].count === 0) {
                await pool.request()
                    .input('title', sql.NVarChar, book.title)
                    .input('author', sql.NVarChar, book.author)
                    .input('userId', sql.NVarChar, userId)
                    .query('INSERT INTO books (title, author, user_id, date_added) VALUES (@title, @author, @userId, GETDATE())');
                
                added++;
            }
        }
        
        res.status(200).json({ 
            message: 'Books processed successfully', 
            total: books.length,
            added: added
        });
        
    } catch (error) {
        console.error('Error processing image:', error);
        res.status(500).json({ message: 'Error processing image' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});