# BookVision

BookVision is a web application that allows users to digitize their book collection using AI. By simply taking a photo of their bookshelf, users can automatically catalog their books without manual entry.

## < Features

- **AI-Powered Scanning**: Uses OpenAI's Vision API to identify books from shelf photos
- **User Authentication**: Secure login via Google Authentication
- **Book Management**: Store, search, sort, and filter your book collection
- **Responsive Design**: Works on desktop and mobile devices

## =€ Getting Started

### Prerequisites

- Node.js (v14 or higher)
- Microsoft SQL Server database
- OpenAI API key
- Google OAuth credentials

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```
# Database Configuration
DB_SERVER=your_sql_server
DB_NAME=your_database_name
DB_USER=your_database_user
DB_PASSWORD=your_database_password

# OpenAI API
OPENAI_API_KEY=your_openai_api_key

# Server Configuration
PORT=3000
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/book-vision-app.git
cd book-vision-app
```

2. Install dependencies:
```bash
npm install
```

3. Set up the database:
```bash
# Run the database setup script on your SQL Server
# You can use SQL Server Management Studio or run:
# sqlcmd -S your_server -U your_user -P your_password -d your_database -i database-setup.sql
```

4. Start the server:
```bash
npm start
```

For development with auto-restart:
```bash
npm run dev
```

5. Access the application:
- Open your browser and navigate to `http://localhost:3000`

## =Ú How It Works

1. **User Authentication**: Users sign in with their Google account
2. **Capture Image**: Take or upload a photo of your bookshelf
3. **AI Processing**: OpenAI Vision API analyzes the image to identify book titles and authors
4. **Database Storage**: Identified books are saved to your personal collection
5. **Collection Management**: Search, sort, and organize your digital book library

## =à Technologies Used

- **Frontend**: HTML, CSS, JavaScript
- **Backend**: Node.js, Express
- **Database**: Microsoft SQL Server
- **Authentication**: Google OAuth (via Azure Static Web Apps Authentication)
- **AI Vision**: OpenAI GPT-4o Vision API
- **File Handling**: Multer

## =Ë API Endpoints

- `GET /books` - Retrieve user's book collection
- `DELETE /books/:id` - Delete a specific book
- `POST /scan` - Upload a bookshelf image for AI processing

## >ê Future Enhancements

- Export book collections in various formats
- Integration with book recommendation systems
- Social sharing features
- Reading progress tracking
- Mobile app version

## =Ý License

This project is licensed under the MIT License - see the LICENSE file for details.

## =O Acknowledgements

- [OpenAI](https://openai.com/) for their powerful Vision API
- [Express.js](https://expressjs.com/) for the web framework
- [Font Awesome](https://fontawesome.com/) for icons