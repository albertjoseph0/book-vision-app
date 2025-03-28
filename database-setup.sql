-- Create the books table
CREATE TABLE books (
    id INT IDENTITY(1,1) PRIMARY KEY,
    title NVARCHAR(255) NOT NULL,
    author NVARCHAR(255) NOT NULL,
    date_added DATETIME DEFAULT GETDATE()
);

-- ALTER TABLE books ADD user_id NVARCHAR(255) NOT NULL DEFAULT 'legacy';
-- ALTER TABLE books ADD user_email NVARCHAR(255);
-- Optional: Add a unique constraint to prevent duplicates
-- ALTER TABLE books ADD CONSTRAINT UQ_books_title_author UNIQUE (title, author);
-- Optional: Create an index for faster searches
CREATE INDEX IX_books_title ON books(title);
CREATE INDEX IX_books_author ON books(author);