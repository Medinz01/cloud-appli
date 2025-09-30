// File: server.js
// This is the main file for your backend API.

// 1. Import Dependencies
const express = require('express');
const mysql = require('mysql2/promise'); // Using the promise-based version
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config(); // To manage database credentials

// 2. Initialize Express App
const app = express();
const PORT = process.env.PORT || 8080;

// 3. Configure Middleware
// --- THIS IS THE CORRECTED SECTION ---
const allowedOrigins = [
  'http://localhost:3000',
  'http://10.208.129.30:3000' // Add your network IP here
];

app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  }
}));
app.use(express.json()); // Allow the server to parse JSON request bodies

// 4. Set Up MySQL Connection
// We create a "pool" of connections for better performance.
const dbPool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '', // Your local MySQL password
  database: process.env.DB_NAME || 'cloud_deployer'
});

// --- API ENDPOINTS ---

// 5. Registration Endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    // Hash the password for security
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Insert the new user into the database
    const [result] = await dbPool.execute(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, passwordHash]
    );

    console.log(`User registered with ID: ${result.insertId}`);
    res.status(201).json({ message: 'User registered successfully!' });

  } catch (error) {
    // Handle potential errors, like a duplicate email
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Email already exists.' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ message: 'An error occurred during registration.' });
  }
});

// 6. Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    // Find the user by email
    const [rows] = await dbPool.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' }); // User not found
    }

    // Compare the provided password with the stored hash
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' }); // Password doesn't match
    }

    // For now, we'll just send a success message.
    // In a real app, you would generate a JWT (JSON Web Token) here.
    console.log(`User logged in: ${user.email}`);
    res.status(200).json({ message: 'Login successful!', user: { email: user.email } });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'An error occurred during login.' });
  }
});

// 7. Endpoint to connect an AWS Account
app.post('/api/account/connect-aws', async (req, res) => {
  try {
    const { email, roleArn } = req.body;

    if (!email || !roleArn) {
      return res.status(400).json({ message: 'Email and Role ARN are required.' });
    }

    // Validate the ARN format (basic check)
    if (!roleArn.startsWith('arn:aws:iam::') || !roleArn.includes(':role/')) {
        return res.status(400).json({ message: 'Invalid IAM Role ARN format.' });
    }

    // Update the user's record in the database
    const [result] = await dbPool.execute(
      'UPDATE users SET aws_role_arn = ? WHERE email = ?',
      [roleArn, email]
    );

    if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'User not found.' });
    }

    console.log(`Updated AWS Role ARN for user: ${email}`);
    res.status(200).json({ message: 'AWS account connected successfully!' });

  } catch (error) {
    console.error('AWS connect error:', error);
    res.status(500).json({ message: 'An error occurred while connecting the AWS account.' });
  }
});


// 8. Start the Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
