require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sql = require('mssql');
const axios = require('axios');
const path = require('path');

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

// Serve static files
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
        // Extract the text content from the response
        const content = responseData.choices[0].message.content;
        
        // Pattern to match books (adjust based on actual response format)
        // This assumes the Vision API returns text with "Title: X, Author: Y" format
        const bookPattern = /Title:\s*([^,;\n]+)[,;\n]\s*Author:\s*([^,;\n]+)/gi;
        
        const books = [];
        let match;
        
        while (match = bookPattern.exec(content)) {
            books.push({
                title: match[1].trim(),
                author: match[2].trim()
            });
        }
        
        return books;
    } catch (error) {
        console.error('Error parsing Vision API response:', error);
        return [];
    }
}

// API Routes

// Get all books
app.get('/books', async (req, res) => {
    try {
        const pool = await getDbPool();
        const result = await pool.request()
            .query('SELECT id, title, author, date_added FROM books ORDER BY date_added DESC');
        
        res.json(result.recordset);
    } catch (error) {
        console.error('Error fetching books:', error);
        res.status(500).json({ message: 'Error fetching books' });
    }
});

// Delete a book
app.delete('/books/:id', async (req, res) => {
    const bookId = req.params.id;
    
    if (!bookId) {
        return res.status(400).json({ message: 'Book ID is required' });
    }
    
    try {
        const pool = await getDbPool();
        const result = await pool.request()
            .input('id', sql.Int, bookId)
            .query('DELETE FROM books WHERE id = @id');
        
        if (result.rowsAffected[0] === 0) {
            return res.status(404).json({ message: 'Book not found' });
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
            model: "gpt-4-vision-preview", // Use the latest vision model
            messages: [
                {
                    role: "user",
                    content: [
                        {
                            type: "text",
                            text: "Identify all books visible in this image. For each book, return the title and author in this format: Title: [Book Title], Author: [Author Name]. Only include books you can clearly see and identify."
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
            max_tokens: 1000
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
        
        for (const book of books) {
            // Check if book already exists
            const existsResult = await pool.request()
                .input('title', sql.NVarChar, book.title)
                .input('author', sql.NVarChar, book.author)
                .query('SELECT COUNT(*) as count FROM books WHERE title = @title AND author = @author');
            
            // If book doesn't exist, add it
            if (existsResult.recordset[0].count === 0) {
                await pool.request()
                    .input('title', sql.NVarChar, book.title)
                    .input('author', sql.NVarChar, book.author)
                    .query('INSERT INTO books (title, author, date_added) VALUES (@title, @author, GETDATE())');
                
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