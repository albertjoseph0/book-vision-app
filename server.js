require('dotenv').config();
const express = require('express');
const multer = require('multer');
const sql = require('mssql');
const axios = require('axios');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const csrf = require('csurf'); // Added for CSRF protection

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Add comprehensive security headers
app.use((req, res, next) => {
    // HSTS header - already implemented
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    // Prevents MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Prevents clickjacking by forbidding your site from being embedded in iframes
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Enables browser's built-in XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Controls referrer information sent with requests
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Content Security Policy - controls which resources can be loaded
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; " +
        "img-src 'self' data: https://source.unsplash.com https://i.pravatar.cc https://*.googleusercontent.com; " +
        "script-src 'self' https://cdnjs.cloudflare.com https://accounts.google.com/gsi/client 'unsafe-inline'; " +
        "style-src 'self' https://cdnjs.cloudflare.com https://accounts.google.com/gsi/style 'unsafe-inline'; " +
        "font-src 'self' https://cdnjs.cloudflare.com; " +
        "frame-src https://accounts.google.com/gsi/ 'self'; " +
        "connect-src 'self' https://accounts.google.com/gsi/ https://api.openai.com https://www.googleapis.com;"
      );
    next();
  });
  
// Apply cookie-parser middleware
app.use(cookieParser());

// Configure secure cookies
app.use((req, res, next) => {
    res.cookie('cookieName', 'cookieValue', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    });
    next();
});

// Parse JSON and urlencoded form data - needed for CSRF to work with forms
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Setup CSRF protection
const csrfProtection = csrf({ 
    cookie: {
        key: '_csrf',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
});

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

// Authentication middleware - Updated to use Azure App Service headers instead of custom token validation
const extractUserIdentity = (req, res, next) => {
    try {
        logInfo('Auth', 'Extracting user identity from Azure App Service headers');
        
        // Check for Azure App Service's principal ID header
        // Note: headers are lowercase in Express
        if (req.headers['x-ms-client-principal-id']) {
            req.user = {
                id: req.headers['x-ms-client-principal-id'],
                email: req.headers['x-ms-client-principal-name'],
                isAuthenticated: true
            };
            
            // Optionally decode the full principal data with all claims
            if (req.headers['x-ms-client-principal']) {
                try {
                    const encoded = req.headers['x-ms-client-principal'];
                    const buff = Buffer.from(encoded, 'base64');
                    const principalData = JSON.parse(buff.toString('ascii'));
                    
                    logInfo('Auth', 'Successfully decoded client principal data', {
                        authType: principalData.auth_typ,
                        claimCount: principalData.claims?.length || 0
                    });
                    
                    // Add all claims to the user object for access in routes
                    req.userClaims = principalData.claims;
                    
                    // Extract additional user information from claims if needed
                    if (principalData.claims && Array.isArray(principalData.claims)) {
                        // Find name claim if available
                        const nameClaim = principalData.claims.find(claim => 
                            claim.typ === 'name' || 
                            claim.typ === 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'
                        );
                        if (nameClaim && !req.user.name) {
                            req.user.name = nameClaim.val;
                        }
                        
                        // Find picture/avatar claim if available
                        const pictureClaim = principalData.claims.find(claim => 
                            claim.typ === 'picture' ||
                            claim.typ === 'urn:google:picture'
                        );
                        if (pictureClaim) {
                            req.user.picture = pictureClaim.val;
                        }
                    }
                } catch (decodeError) {
                    logError('Auth', 'Error decoding client principal data', decodeError);
                }
            }
            
            logInfo('Auth', 'User authenticated via Azure App Service', {
                id: req.user.id,
                email: req.user.email
            });
        } else {
            // No Azure auth headers found - user is not authenticated
            logInfo('Auth', 'No Azure authentication headers found, user is anonymous');
            req.user = {
                id: 'anonymous',
                isAuthenticated: false
            };
            
            // For debugging purposes in development
            if (process.env.NODE_ENV === 'development') {
                logInfo('Auth', 'Available request headers', {
                    headerKeys: Object.keys(req.headers)
                });
            }
        }
    } catch (error) {
        // Handle any errors during authentication processing
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

// NEW: Database rate limiter middleware
// Replaces the express-rate-limit package with database-driven rate limiting
const dbScanRateLimiter = async (req, res, next) => {
    try {
        logInfo('RateLimit', 'Checking scan rate limit', {
            userId: req.user.id
        });
        
        if (!req.user || !req.user.id || req.user.id === 'anonymous') {
            logError('RateLimit', 'User not properly authenticated for rate limiting');
            return res.status(401).json({
                status: 'error',
                message: 'Authentication required for this operation'
            });
        }
        
        const pool = await getDbPool();
        
        // Count scans in the last 24 hours for this user
        const query = `
            SELECT COUNT(*) as scan_count 
            FROM user_scans 
            WHERE user_id = @userId 
            AND scan_time > DATEADD(hour, -24, GETDATE())
        `;
        
        const countResult = await pool.request()
            .input('userId', sql.NVarChar, req.user.id)
            .query(query);
        
        const scanCount = countResult.recordset[0].scan_count;
        
        logInfo('RateLimit', 'User scan count in last 24 hours', {
            userId: req.user.id,
            scanCount: scanCount,
            limit: 10
        });
        
        // Check if user has reached the limit (10 scans per 24 hours)
        if (scanCount >= 10) {
            logInfo('RateLimit', 'Scan rate limit reached', {
                userId: req.user.id,
                scanCount: scanCount
            });
            
            return res.status(429).json({
                status: 'error',
                message: 'Too many upload requests. Limit is 10 uploads per day per user.'
            });
        }
        
        // Add rate limit headers for consistent client experience
        res.setHeader('X-RateLimit-Limit', 10);
        res.setHeader('X-RateLimit-Remaining', 10 - scanCount);
        
        // Continue to the next middleware
        next();
    } catch (error) {
        logError('RateLimit', 'Error checking scan rate limit', error);
        
        // In case of database error, allow the request to proceed
        // to prevent blocking users due to our system error
        next();
    }
};

// New function to record successful scans
async function recordSuccessfulScan(userId, fileName = null) {
    try {
        logInfo('RateLimit', 'Recording successful scan', {
            userId: userId,
            fileName: fileName
        });
        
        const pool = await getDbPool();
        
        // Insert record of successful scan
        const query = `
            INSERT INTO user_scans (user_id, scan_file_name, scan_status) 
            VALUES (@userId, @fileName, 'completed')
        `;
        
        await pool.request()
            .input('userId', sql.NVarChar, userId)
            .input('fileName', sql.NVarChar, fileName || null)
            .query(query);
        
        logInfo('RateLimit', 'Successfully recorded scan in database');
        
        return true;
    } catch (error) {
        logError('RateLimit', 'Error recording scan in database', error);
        return false;
    }
}

// Function to fetch ISBN from Google Books API
async function fetchISBN(title, author) {
    try {
        logInfo('GoogleBooks', 'Fetching ISBN for book', {
            title: title,
            author: author
        });
        
        // Encode title and author for URL
        const encodedTitle = encodeURIComponent(title);
        const encodedAuthor = encodeURIComponent(author);
        
        // Construct Google Books API URL
        const url = `https://www.googleapis.com/books/v1/volumes?q=intitle:${encodedTitle}+inauthor:${encodedAuthor}&maxResults=1`;
        
        logInfo('GoogleBooks', 'Calling Google Books API', { url });
        
        // Make request to Google Books API
        const response = await axios.get(url);
        
        logInfo('GoogleBooks', 'Google Books API response received', {
            status: response.status,
            itemCount: response.data.totalItems
        });
        
        // Check if any books were found
        if (response.data.totalItems === 0 || !response.data.items || !response.data.items[0]) {
            logInfo('GoogleBooks', 'No books found in Google Books API', {
                title,
                author
            });
            return 'N/A';
        }
        
        // Get the first book result
        const book = response.data.items[0];
        
        // Extract ISBN-13 from industry identifiers if available
        if (book.volumeInfo && 
            book.volumeInfo.industryIdentifiers && 
            Array.isArray(book.volumeInfo.industryIdentifiers)) {
            
            // Look for ISBN_13 specifically
            const isbn13 = book.volumeInfo.industryIdentifiers.find(
                id => id.type === 'ISBN_13'
            );
            
            if (isbn13 && isbn13.identifier) {
                logInfo('GoogleBooks', 'ISBN-13 found', {
                    isbn: isbn13.identifier,
                    title,
                    author
                });
                return isbn13.identifier;
            }
            
            // If no ISBN-13, try ISBN_10
            const isbn10 = book.volumeInfo.industryIdentifiers.find(
                id => id.type === 'ISBN_10'
            );
            
            if (isbn10 && isbn10.identifier) {
                logInfo('GoogleBooks', 'ISBN-10 found (no ISBN-13 available)', {
                    isbn: isbn10.identifier,
                    title,
                    author
                });
                return isbn10.identifier;
            }
        }
        
        logInfo('GoogleBooks', 'No ISBN found in Google Books API response', {
            title,
            author
        });
        return 'N/A';
        
    } catch (error) {
        logError('GoogleBooks', `Error fetching ISBN for "${title}" by ${author}`, error);
        return 'N/A';
    }
}

// Error handler for CSRF errors
app.use(function (err, req, res, next) {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);
    
    // Handle CSRF token errors
    logError('CSRF', 'Invalid CSRF token', err);
    res.status(403).json({
        status: 'error',
        message: 'Security validation failed. Please refresh the page and try again.'
    });
});

// Set landing page as the default route
app.get('/', (req, res) => {
    logInfo('Routes', 'Serving landing page');
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// Route for the main app after clicking 'Get Started' or any CTA button
// Now protected with authentication requirement
app.get('/app', requireAuth, csrfProtection, (req, res) => {
    logInfo('Routes', 'Serving main app page to authenticated user', {
        userId: req.user.id,
        userEmail: req.user.email
    });
    
    // Render the page with the CSRF token
    res.setHeader('Content-Type', 'text/html');
    const html = require('fs').readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8')
        .replace('<!-- CSRF_TOKEN -->', `<meta name="csrf-token" content="${req.csrfToken()}">`);
    
    res.send(html);
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
        const requiredColumns = ['id', 'title', 'author', 'date_added', 'user_id', 'user_email', 'isbn'];
        const missingColumns = requiredColumns.filter(col => !columns.includes(col));
        
        // Check if the user_scans table exists
        const userScansTableResult = await pool.request().query(`
            SELECT COUNT(*) as table_exists
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_NAME = 'user_scans'
        `);
        
        const userScansTableExists = userScansTableResult.recordset[0].table_exists > 0;
        logInfo('Database', 'user_scans table exists:', userScansTableExists);
        
        if (missingColumns.length > 0) {
            logError('Database', 'Missing required columns in books table', missingColumns);
        } else {
            logInfo('Database', 'All required columns present in books table');
        }
        
        // Check for user_scans table schema if it exists
        let userScanColumns = [];
        if (userScansTableExists) {
            const scanColumnsResult = await pool.request().query(`
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = 'user_scans'
            `);
            
            userScanColumns = scanColumnsResult.recordset.map(record => record.COLUMN_NAME);
            logInfo('Database', 'Found columns in user_scans table', userScanColumns);
        }
        
        return {
            valid: missingColumns.length === 0 && userScansTableExists,
            booksColumns: columns,
            missingBooksColumns: missingColumns,
            userScansTableExists: userScansTableExists,
            userScansColumns: userScanColumns
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

// CSRF token endpoint
app.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Get all books - protected with authentication
app.get('/books', requireAuth, csrfProtection, async (req, res) => {
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
            SELECT id, title, author, date_added, user_email, isbn
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
        
        // Include CSRF token with the response
        res.json({
            books: result.recordset,
            csrfToken: req.csrfToken()
        });
        
    } catch (error) {
        logError('API', 'Error fetching books', error);
        res.status(500).json({ message: 'Error fetching books', error: error.message });
    }
});

// Delete a book (secure version) - protected with authentication and CSRF
app.delete('/books/:id', requireAuth, csrfProtection, async (req, res) => {
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
        
        res.status(200).json({ 
            message: 'Book deleted successfully',
            csrfToken: req.csrfToken() // Send a new token for the next operation
        });
        
    } catch (error) {
        logError('API', 'Error deleting book', error);
        res.status(500).json({ message: 'Error deleting book', error: error.message });
    }
});

// Scan and process bookshelf photo - protected with authentication and CSRF
// Now uses database rate limiting middleware instead of express-rate-limit
app.post('/scan', requireAuth, dbScanRateLimiter, csrfProtection, upload.single('photo'), async (req, res) => {
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
            model: "gpt-4o-mini",
            messages: [
                {
                    role: "user",
                    content: [
                        {
                            type: "text",
                            text: "You are a book identification expert. Identify all visible book titles and authors in the image. Respond in JSON format with an array of books containing title and author fields."
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
            
            // Record the scan attempt even if no books were found
            await recordSuccessfulScan(req.user.id, req.file.originalname || 'unnamed_file');
            
            return res.status(200).json({ 
                message: 'No books detected in the image', 
                added: 0,
                csrfToken: req.csrfToken() // Send a new token for the next operation
            });
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
        
        // Get ISBNs for all books first (in parallel)
        const bookPromises = books.map(async (book) => {
            try {
                // Add a small delay between API calls to avoid rate limiting
                const isbn = await fetchISBN(book.title, book.author);
                return { ...book, isbn };
            } catch (error) {
                logError('API', `Error fetching ISBN for book: ${book.title}`, error);
                return { ...book, isbn: 'N/A' };
            }
        });
        
        // Wait for all ISBN lookups to complete
        const booksWithISBN = await Promise.all(bookPromises);
        
        logInfo('API', 'Completed ISBN lookups for all books', {
            booksWithISBN: booksWithISBN.map(b => ({ title: b.title, isbn: b.isbn }))
        });
        
        // Now insert books with their ISBNs
        for (const book of booksWithISBN) {
            // Skip invalid books (extra safety check)
            if (!book.title || !book.author) {
                logInfo('API', 'Skipping invalid book', book);
                continue;
            }
            
            // Check if book already exists for this user
            const existsQuery = 'SELECT id FROM books WHERE title = @title AND author = @author AND user_id = @userId';
            
            const existsResult = await pool.request()
                .input('title', sql.NVarChar, book.title)
                .input('author', sql.NVarChar, book.author)
                .input('userId', sql.NVarChar, userId)
                .query(existsQuery);
            
            const bookExists = existsResult.recordset.length > 0;
            
            if (!bookExists) {
                // If book doesn't exist, insert it with ISBN
                const insertQuery = 'INSERT INTO books (title, author, user_id, user_email, date_added, isbn) VALUES (@title, @author, @userId, @userEmail, GETDATE(), @isbn)';
                
                try {
                    const insertResult = await pool.request()
                        .input('title', sql.NVarChar, book.title)
                        .input('author', sql.NVarChar, book.author)
                        .input('userId', sql.NVarChar, userId)
                        .input('userEmail', sql.NVarChar, userEmail)
                        .input('isbn', sql.NVarChar, book.isbn)
                        .query(insertQuery);
                    
                    logInfo('API', 'Book insert result', {
                        rowsAffected: insertResult.rowsAffected[0],
                        book: book
                    });
                    
                    added++;
                } catch (insertError) {
                    logError('API', `Error inserting book: ${book.title} by ${book.author}`, insertError);
                }
            } else {
                // Book exists, update its ISBN if needed
                const existingBookId = existsResult.recordset[0].id;
                
                // Update ISBN if it's not already set
                const updateQuery = `
                    UPDATE books 
                    SET isbn = @isbn 
                    WHERE id = @id AND (isbn IS NULL OR isbn = 'N/A')
                `;
                
                await pool.request()
                    .input('isbn', sql.NVarChar, book.isbn)
                    .input('id', sql.Int, existingBookId)
                    .query(updateQuery);
                
                logInfo('API', 'Updated existing book ISBN', {
                    bookId: existingBookId,
                    isbn: book.isbn
                });
            }
        }
        
        logInfo('API', 'Book insertion process completed', {
            totalProcessed: books.length,
            added: added
        });
        
        // Record successful scan in the user_scans table
        await recordSuccessfulScan(req.user.id, req.file.originalname || 'unnamed_file');
        
        res.status(200).json({ 
            message: 'Books processed successfully', 
            total: books.length,
            added: added,
            csrfToken: req.csrfToken() // Send a new token for the next operation
        });
        
    } catch (error) {
        logError('API', 'Error processing image', error);
        res.status(500).json({ message: 'Error processing image', error: error.message });
    }
});

// Add a diagnostic endpoint to check database connection and schema
app.get('/api/diagnostics', requireAuth, csrfProtection, async (req, res) => {
    logInfo('API', 'Database diagnostics request');
    
    try {
        // Verify database schema
        const schemaVerification = await verifyDatabaseSchema();
        
        // Test database connection
        const pool = await getDbPool();
        const connectionTest = { success: true };
        
        // Get scan usage information
        const scanUsageQuery = `
            SELECT COUNT(*) as total_scans,
                   COUNT(CASE WHEN scan_time > DATEADD(hour, -24, GETDATE()) THEN 1 END) as scans_last_24h
            FROM user_scans 
            WHERE user_id = @userId
        `;
        
        const scanUsageResult = await pool.request()
            .input('userId', sql.NVarChar, req.user.id)
            .query(scanUsageQuery);
        
        const scanUsage = scanUsageResult.recordset[0];
        
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
        
        // Get a list of Azure App Service auth headers for debugging
        const azureAuthHeaders = {
            'x-ms-client-principal-id': req.headers['x-ms-client-principal-id'] ? 'present' : 'absent',
            'x-ms-client-principal-name': req.headers['x-ms-client-principal-name'] ? 'present' : 'absent',
            'x-ms-client-principal': req.headers['x-ms-client-principal'] ? 'present' : 'absent',
            'x-ms-client-principal-idp': req.headers['x-ms-client-principal-idp'] ? 'present' : 'absent',
            otherHeaders: Object.keys(req.headers).filter(h => h.startsWith('x-ms-'))
        };
        
        res.json({
            timestamp: new Date().toISOString(),
            database: {
                connection: connectionTest,
                schema: schemaVerification
            },
            rateLimit: {
                scanUsage: scanUsage,
                remainingToday: 10 - (scanUsage.scans_last_24h || 0)
            },
            user: {
                id: req.user.id,
                email: req.user.email,
                isAuthenticated: req.user.isAuthenticated
            },
            azureAuthHeaders: azureAuthHeaders,
            system: systemInfo,
            csrfToken: req.csrfToken() // Include CSRF token
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
app.get('/api/auth-status', csrfProtection, async (req, res) => {
    logInfo('API', 'Auth status check requested');
    
    // Check available authentication sources
    const azureAuthHeaders = {
        'x-ms-client-principal-id': req.headers['x-ms-client-principal-id'] ? 'present' : 'absent',
        'x-ms-client-principal-name': req.headers['x-ms-client-principal-name'] ? 'present' : 'absent',
        'x-ms-client-principal': req.headers['x-ms-client-principal'] ? 'present' : 'absent',
        'x-ms-client-principal-idp': req.headers['x-ms-client-principal-idp'] ? 'present' : 'absent'
    };
    
    res.json({
        authenticated: req.user.isAuthenticated,
        userId: req.user.id,
        userEmail: req.user.email,
        userName: req.user.name,
        userPicture: req.user.picture,
        azureAuthHeaders: azureAuthHeaders,
        csrfToken: req.csrfToken() // Include CSRF token
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
            
            // Check if user_scans table exists, create it if needed
            if (!result.userScansTableExists) {
                console.error('Missing user_scans table - attempting to create it');
                
                // Create the user_scans table
                getDbPool().then(pool => {
                    return pool.request().query(`
                        CREATE TABLE user_scans (
                            id INT IDENTITY(1,1) PRIMARY KEY,
                            user_id NVARCHAR(255) NOT NULL,
                            scan_time DATETIME DEFAULT GETDATE(),
                            scan_file_name NVARCHAR(255) NULL,
                            scan_status NVARCHAR(50) DEFAULT 'completed'
                        );
                    `);
                })
                .then(() => {
                    console.log('Successfully created user_scans table');
                })
                .catch(err => {
                    console.error('Failed to create user_scans table:', err);
                });
            }
            
            // Check if ISBN column exists, add it if needed
            if (result.missingBooksColumns.includes('isbn')) {
                console.error('Missing isbn column in books table - attempting to add it');
                
                // Add the ISBN column
                getDbPool().then(pool => {
                    return pool.request().query(`
                        ALTER TABLE books ADD isbn NVARCHAR(20);
                        CREATE INDEX IX_books_isbn ON books(isbn);
                    `);
                })
                .then(() => {
                    console.log('Successfully added isbn column to books table');
                })
                .catch(err => {
                    console.error('Failed to add isbn column:', err);
                });
            }
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