require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sql = require('mssql');
const axios = require('axios');
const path = require('path');
const cookieParser = require('cookie-parser'); // Add cookie-parser
const jwt = require('jsonwebtoken');
// At the top of your file
const {OAuth2Client} = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID); // Add this to your .env file

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Apply cookie-parser middleware
app.use(cookieParser());

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

// Enhanced logging function
function logInfo(context, message, data = null) {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] [INFO] [${context}] ${message}`);
    if (data) {
        console.log(JSON.stringify(data, null, 2));
    }
}

function logError(context, message, error) {
    const timestamp = new Date().toISOString();
    console.error(`[${timestamp}] [ERROR] [${context}] ${message}`);
    if (error) {
        if (error.stack) {
            console.error(error.stack);
        } else {
            console.error(JSON.stringify(error, null, 2));
        }
    }
}

// Authentication middleware - updated to verify tokens properly
const extractUserIdentity = async (req, res, next) => {
  try {
    logInfo('Auth', 'Extracting user identity from request');
    
    // Get the Google ID token from multiple possible sources
    let googleIdToken = null;
    
    // 1. Check standard header (from Azure Static Web Apps)
    if (req.headers['x-ms-token-google-id-token']) {
      googleIdToken = req.headers['x-ms-token-google-id-token'];
      logInfo('Auth', 'Found Google ID token in headers');
    } 
    // 2. Check cookies (Azure Static Web Apps auth cookie)
    else if (req.cookies && req.cookies['AppServiceAuthSession']) {
      googleIdToken = req.cookies['AppServiceAuthSession'];
      logInfo('Auth', 'Found Google ID token in cookies');
    }
    // 3. Check for custom auth header
    else if (req.headers['authorization'] && req.headers['authorization'].startsWith('Bearer ')) {
      googleIdToken = req.headers['authorization'].substring(7);
      logInfo('Auth', 'Found Google ID token in Authorization header');
    }
    
    if (googleIdToken) {
      // Log the token format (without revealing the full token)
      const tokenPreview = googleIdToken.substring(0, 20) + '...' + googleIdToken.substring(googleIdToken.length - 10);
      logInfo('Auth', `Token format: ${tokenPreview}`);
      
      try {
        // Properly verify the token instead of just decoding it
        const ticket = await client.verifyIdToken({
          idToken: googleIdToken,
          audience: process.env.GOOGLE_CLIENT_ID,
        });
        
        // Get the payload from the verified token
        const payload = ticket.getPayload();
        
        // Extract user information from verified token payload
        req.user = {
          id: payload.sub,
          email: payload.email,
          name: payload.name,
          isAuthenticated: true
        };
        
        logInfo('Auth', 'Successfully verified user identity', {
          id: req.user.id,
          email: req.user.email,
          name: req.user.name
        });
      } catch (verificationError) {
        // Token verification failed
        logError('Auth', 'Token verification failed', verificationError);
        
        // For security, treat failed verification as unauthenticated
        req.user = { id: 'anonymous', isAuthenticated: false };
        
        // For debugging purposes, log available headers and cookies
        logInfo('Auth', 'Available request headers', {
          headers: Object.keys(req.headers),
          cookies: req.cookies ? Object.keys(req.cookies) : 'none'
        });
      }
    } else {
      // No token found
      logInfo('Auth', 'No token found, setting anonymous user');
      
      // For debugging purposes, log all available headers and cookies
      logInfo('Auth', 'Available authentication sources', {
        headers: Object.keys(req.headers),
        cookies: req.cookies ? Object.keys(req.cookies) : 'none'
      });
      
      req.user = {
        id: 'anonymous',
        isAuthenticated: false
      };
    }
  } catch (error) {
    // Handle any other errors
    logError('Auth', 'Error extracting user identity', error);
    
    // Set default user for error cases
    req.user = {
      id: 'anonymous',
      isAuthenticated: false
    };
  }
  
  // Always continue to the next middleware
  next();
};

// Authentication check middleware - redirects to landing page if not authenticated
const requireAuth = (req, res, next) => {
    logInfo('Auth', `Authentication check for route: ${req.path}`, {
        isAuthenticated: req.user?.isAuthenticated,
        userId: req.user?.id
    });
    
    if (req.user && req.user.isAuthenticated) {
        next();
    } else {
        logInfo('Auth', 'Redirecting unauthenticated user to landing page');
        res.redirect('/'); // Redirect to landing page
    }
};

// Apply the authentication middleware to all routes
app.use(extractUserIdentity);

// Set landing page as the default route
app.get('/', (req, res) => {
    logInfo('Routes', 'Serving landing page');
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// Route for the main app after clicking 'Get Started' or any CTA button
// Now protected with authentication requirement
app.get('/app', requireAuth, (req, res) => {
    logInfo('Routes', 'Serving main app page to authenticated user', {
        userId: req.user.id,
        userEmail: req.user.email
    });
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

// Log database config (without sensitive info)
logInfo('Database', 'Database configuration', {
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    passwordProvided: !!process.env.DB_PASSWORD
});

// OpenAI API configuration
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions';

// Connect to database and return a pool
async function getDbPool() {
    try {
        logInfo('Database', 'Attempting to connect to database');
        const pool = await sql.connect(dbConfig);
        logInfo('Database', 'Successfully connected to database');
        return pool;
    } catch (err) {
        logError('Database', 'Database connection error', err);
        throw new Error('Failed to connect to database');
    }
}

// Database schema verification function
async function verifyDatabaseSchema() {
    try {
        logInfo('Database', 'Verifying database schema');
        const pool = await getDbPool();
        
        // Check if the books table exists and has the required columns
        const tableResult = await pool.request().query(`
            SELECT COLUMN_NAME 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_NAME = 'books'
        `);
        
        const columns = tableResult.recordset.map(record => record.COLUMN_NAME);
        logInfo('Database', 'Found columns in books table', columns);
        
        // Check for required columns
        const requiredColumns = ['id', 'title', 'author', 'date_added', 'user_id', 'user_email'];
        const missingColumns = requiredColumns.filter(col => !columns.includes(col));
        
        if (missingColumns.length > 0) {
            logError('Database', 'Missing required columns in books table', missingColumns);
        } else {
            logInfo('Database', 'All required columns present in books table');
        }
        
        return {
            valid: missingColumns.length === 0,
            columns: columns,
            missingColumns: missingColumns
        };
    } catch (error) {
        logError('Database', 'Error verifying database schema', error);
        return {
            valid: false,
            error: error.message
        };
    }
}

// Helper function to parse OpenAI Vision API response
function parseVisionResponse(responseData) {
    try {
        logInfo('Vision', 'Parsing Vision API response');
        
        // Make sure we have a response with content
        if (!responseData?.choices?.[0]?.message?.content) {
            logError('Vision', 'Invalid response format from Vision API', responseData);
            return [];
        }
        
        // Extract the content from the response
        const content = responseData.choices[0].message.content;
        logInfo('Vision', 'Raw content from Vision API', { content });
        
        // Since we requested JSON format, try to parse the content as JSON
        let books = [];
        
        try {
            // Parse the JSON string from the content
            const parsedContent = JSON.parse(content);
            logInfo('Vision', 'Successfully parsed JSON from Vision API', parsedContent);
            
            // Check if the response contains a books array
            if (Array.isArray(parsedContent.books)) {
                books = parsedContent.books;
                logInfo('Vision', 'Found books array in response', { count: books.length });
            } 
            // Or if the response itself is an array
            else if (Array.isArray(parsedContent)) {
                books = parsedContent;
                logInfo('Vision', 'Response is an array of books', { count: books.length });
            } else {
                logInfo('Vision', 'Unexpected response structure', parsedContent);
            }
            
            // Log the raw books data before filtering
            logInfo('Vision', 'Books before filtering', books);
            
            // Filter to ensure each book has both title and author
            books = books.filter(book => 
                book && 
                typeof book === 'object' && 
                typeof book.title === 'string' && 
                typeof book.author === 'string' &&
                book.title.trim() !== '' && 
                book.author.trim() !== ''
            );
            
            logInfo('Vision', 'Books after filtering', { 
                count: books.length,
                books: books
            });
            
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
            
            logInfo('Vision', 'Final unique books', { 
                count: uniqueBooks.length,
                books: uniqueBooks
            });
            
            return uniqueBooks;
            
        } catch (jsonError) {
            logError('Vision', 'Failed to parse JSON from Vision API response', jsonError);
            logInfo('Vision', 'Raw content received', { content });
            return [];
        }
    } catch (error) {
        logError('Vision', 'Error parsing Vision API response', error);
        return [];
    }
}

// API Routes

// Get all books - protected with authentication
app.get('/books', requireAuth, async (req, res) => {
    logInfo('API', 'Books GET request', {
        userId: req.user.id,
        userEmail: req.user.email
    });
    
    try {
        const pool = await getDbPool();
        let query = '';
        let request = pool.request();
        
        // User is authenticated (we know this because of requireAuth middleware)
        query = `
            SELECT id, title, author, date_added, user_email 
            FROM books 
            WHERE user_id = @userId
            ORDER BY date_added DESC
        `;
        request.input('userId', sql.NVarChar, req.user.id);
        
        logInfo('API', 'Executing books query', {
            query: query,
            parameters: { userId: req.user.id }
        });
        
        const result = await request.query(query);
        
        logInfo('API', 'Books query result', {
            rowCount: result.recordset.length,
            firstFewBooks: result.recordset.slice(0, 3)
        });
        
        res.json(result.recordset);
        
    } catch (error) {
        logError('API', 'Error fetching books', error);
        res.status(500).json({ message: 'Error fetching books', error: error.message });
    }
});

// Delete a book (secure version) - protected with authentication
app.delete('/books/:id', requireAuth, async (req, res) => {
    const bookId = req.params.id;
    
    logInfo('API', 'Delete book request', {
        bookId: bookId,
        userId: req.user.id
    });
    
    if (!bookId) {
        logError('API', 'Delete book request missing ID');
        return res.status(400).json({ message: 'Book ID is required' });
    }
    
    try {
        const pool = await getDbPool();
        
        const query = 'DELETE FROM books WHERE id = @id AND user_id = @userId';
        logInfo('API', 'Executing delete query', {
            query: query,
            parameters: { id: bookId, userId: req.user.id }
        });
        
        // Delete the book only if it belongs to this user
        const deleteResult = await pool.request()
            .input('id', sql.Int, bookId)
            .input('userId', sql.NVarChar, req.user.id)
            .query(query);
        
        logInfo('API', 'Delete query result', {
            rowsAffected: deleteResult.rowsAffected[0]
        });
        
        // Check if any rows were affected
        if (deleteResult.rowsAffected[0] === 0) {
            logInfo('API', 'No rows deleted - book not found or permission denied');
            return res.status(403).json({ 
                message: 'Book not found or you do not have permission to delete it'
            });
        }
        
        res.status(200).json({ message: 'Book deleted successfully' });
        
    } catch (error) {
        logError('API', 'Error deleting book', error);
        res.status(500).json({ message: 'Error deleting book', error: error.message });
    }
});

// Scan and process bookshelf photo - protected with authentication
app.post('/scan', requireAuth, upload.single('photo'), async (req, res) => {
    logInfo('API', 'Scan photo request received', {
        userId: req.user.id,
        userEmail: req.user.email,
        fileReceived: !!req.file,
        fileSize: req.file?.size
    });
    
    if (!req.file) {
        logError('API', 'No photo uploaded in scan request');
        return res.status(400).json({ message: 'No photo uploaded' });
    }
    
    try {
        // Convert image buffer to base64
        const base64Image = req.file.buffer.toString('base64');
        logInfo('API', 'Image converted to base64', {
            base64Length: base64Image.length
        });
        
        // Prepare OpenAI Vision API request
        const requestData = {
            model: "gpt-4o",
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
        };
        
        logInfo('API', 'Calling OpenAI Vision API', {
            model: requestData.model,
            max_tokens: requestData.max_tokens,
            response_format: requestData.response_format
        });
        
        // Call OpenAI Vision API
        const response = await axios.post(OPENAI_API_URL, requestData, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            }
        });
        
        logInfo('API', 'Received response from OpenAI Vision API', {
            status: response.status,
            responseSize: JSON.stringify(response.data).length
        });
        
        // Parse the response to extract book information
        const books = parseVisionResponse(response.data);
        
        if (books.length === 0) {
            logInfo('API', 'No books detected in the image');
            return res.status(200).json({ message: 'No books detected in the image', added: 0 });
        }
        
        // Verify database schema before proceeding
        const schemaVerification = await verifyDatabaseSchema();
        logInfo('API', 'Database schema verification result', schemaVerification);
        
        // Add books to database (avoiding duplicates)
        const pool = await getDbPool();
        let added = 0;
        
        // Use the authenticated user's ID
        const userId = req.user.id;
        const userEmail = req.user.email || null;
        
        logInfo('API', 'Starting book insertion process', {
            totalBooks: books.length,
            userId: userId,
            userEmail: userEmail
        });
        
        for (const book of books) {
            // Skip invalid books (extra safety check)
            if (!book.title || !book.author) {
                logInfo('API', 'Skipping invalid book', book);
                continue;
            }
            
            // Check if book already exists for this user
            const existsQuery = 'SELECT COUNT(*) as count FROM books WHERE title = @title AND author = @author AND user_id = @userId';
            logInfo('API', 'Checking if book exists', {
                query: existsQuery,
                parameters: {
                    title: book.title,
                    author: book.author,
                    userId: userId
                }
            });
            
            const existsResult = await pool.request()
                .input('title', sql.NVarChar, book.title)
                .input('author', sql.NVarChar, book.author)
                .input('userId', sql.NVarChar, userId)
                .query(existsQuery);
            
            logInfo('API', 'Book existence check result', {
                book: book,
                exists: existsResult.recordset[0].count > 0,
                count: existsResult.recordset[0].count
            });
            
            // If book doesn't exist for this user, add it
            if (existsResult.recordset[0].count === 0) {
                const insertQuery = 'INSERT INTO books (title, author, user_id, user_email, date_added) VALUES (@title, @author, @userId, @userEmail, GETDATE())';
                logInfo('API', 'Inserting new book', {
                    query: insertQuery,
                    parameters: {
                        title: book.title,
                        author: book.author,
                        userId: userId,
                        userEmail: userEmail
                    }
                });
                
                try {
                    const insertResult = await pool.request()
                        .input('title', sql.NVarChar, book.title)
                        .input('author', sql.NVarChar, book.author)
                        .input('userId', sql.NVarChar, userId)
                        .input('userEmail', sql.NVarChar, userEmail)
                        .query(insertQuery);
                    
                    logInfo('API', 'Book insert result', {
                        rowsAffected: insertResult.rowsAffected[0],
                        book: book
                    });
                    
                    added++;
                } catch (insertError) {
                    logError('API', `Error inserting book: ${book.title} by ${book.author}`, insertError);
                }
            }
        }
        
        logInfo('API', 'Book insertion process completed', {
            totalProcessed: books.length,
            added: added
        });
        
        res.status(200).json({ 
            message: 'Books processed successfully', 
            total: books.length,
            added: added
        });
        
    } catch (error) {
        logError('API', 'Error processing image', error);
        res.status(500).json({ message: 'Error processing image', error: error.message });
    }
});

// Add a diagnostic endpoint to check database connection and schema
app.get('/api/diagnostics', requireAuth, async (req, res) => {
    logInfo('API', 'Database diagnostics request');
    
    try {
        // Verify database schema
        const schemaVerification = await verifyDatabaseSchema();
        
        // Test database connection
        const pool = await getDbPool();
        const connectionTest = { success: true };
        
        // Get some system information
        const systemInfo = {
            nodeVersion: process.version,
            platform: process.platform,
            memoryUsage: process.memoryUsage(),
            env: {
                PORT: process.env.PORT,
                DB_SERVER: process.env.DB_SERVER,
                DB_NAME: process.env.DB_NAME,
                DB_USER: process.env.DB_USER,
                hasOpenAiKey: !!process.env.OPENAI_API_KEY
            }
        };
        
        // Get a list of auth related headers and cookies
        const authSources = {
            headers: {
                'x-ms-token-google-id-token': !!req.headers['x-ms-token-google-id-token'],
                'authorization': req.headers['authorization'] ? 'present' : 'absent',
                otherHeaders: Object.keys(req.headers)
            },
            cookies: req.cookies ? Object.keys(req.cookies) : []
        };
        
        res.json({
            timestamp: new Date().toISOString(),
            database: {
                connection: connectionTest,
                schema: schemaVerification
            },
            user: {
                id: req.user.id,
                email: req.user.email,
                isAuthenticated: req.user.isAuthenticated
            },
            authSources: authSources,
            system: systemInfo
        });
    } catch (error) {
        logError('API', 'Error in diagnostics endpoint', error);
        res.status(500).json({
            error: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Add an endpoint to check current auth status
app.get('/api/auth-status', async (req, res) => {
    logInfo('API', 'Auth status check requested');
    
    // Check available authentication sources
    const authSources = {
        headers: {
            'x-ms-token-google-id-token': req.headers['x-ms-token-google-id-token'] ? 'present' : 'absent',
            'authorization': req.headers['authorization'] ? 'present' : 'absent',
        },
        cookies: req.cookies ? Object.keys(req.cookies) : [],
        user: {
            id: req.user.id,
            isAuthenticated: req.user.isAuthenticated
        }
    };
    
    res.json({
        authenticated: req.user.isAuthenticated,
        userId: req.user.id,
        userEmail: req.user.email,
        authSources: authSources
    });
});

// Run database schema verification on startup
verifyDatabaseSchema()
    .then(result => {
        if (!result.valid) {
            logError('Startup', 'Database schema verification failed', result);
            console.error('\n=======================================');
            console.error('WARNING: DATABASE SCHEMA ISSUES DETECTED');
            console.error('=======================================\n');
        } else {
            logInfo('Startup', 'Database schema verification passed');
        }
    })
    .catch(error => {
        logError('Startup', 'Failed to verify database schema', error);
    });

// Start server
app.listen(PORT, () => {
    logInfo('Server', `Server running on port ${PORT}`);
    console.log(`\n==========================================`);
    console.log(`Book Vision API Server started on port ${PORT}`);
    console.log(`Database: ${process.env.DB_NAME} on ${process.env.DB_SERVER}`);
    console.log(`==========================================\n`);
});