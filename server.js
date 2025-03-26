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

// Connect to database and return a pool
async function getDbPool() {
    try {
        const pool = await sql.connect(dbConfig);
        console.log('Database connected successfully');
        return pool;
    } catch (err) {
        console.error('Database connection error:', err);
        throw new Error('Failed to connect to database');
    }
}

// OpenAI API service for book detection
async function detectBooksInImage(base64Image) {
    try {
        console.log('Calling OpenAI API...');
        
        // Call OpenAI Vision API directly with environment variable
        const response = await axios.post(
            'https://api.openai.com/v1/chat/completions',
            {
                model: process.env.OPENAI_MODEL || "gpt-4o-mini",
                messages: [
                    {
                        role: "user",
                        content: [
                            {
                                type: "text",
                                text: "Identify all book titles and authors visible on the book spines in this bookshelf image. Return a JSON array with objects containing only 'title' and 'author' for each book you can identify. Focus only on clearly readable text on the spines."
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
            },
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
                }
            }
        );
        
        console.log('OpenAI API response received');
        
        // Parse the response to extract book data
        const content = response.data.choices[0].message.content;
        console.log('OpenAI content response:', content.substring(0, 100) + '...');
        
        // Extract JSON array from the response content
        // This handles cases where the API might return extra text surrounding the JSON
        const jsonMatch = content.match(/\[[\s\S]*\]/);
        let booksData = [];
        
        if (jsonMatch) {
            booksData = JSON.parse(jsonMatch[0]);
            console.log('Parsed books data successfully');
        } else {
            throw new Error('Could not parse JSON response from OpenAI');
        }
        
        return booksData;
    } catch (error) {
        console.error('OpenAI API error:', error.message);
        throw new Error(`Failed to process image with OpenAI: ${error.message}`);
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

// Scan and process bookshelf photo
app.post('/scan', upload.single('photo'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No photo uploaded' });
    }
    
    try {
        // Convert image buffer to base64
        const base64Image = req.file.buffer.toString('base64');
        
        // Call our book detection function
        const books = await detectBooksInImage(base64Image);
        
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