require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const multer = require('multer');

const app = express();
// Keep your existing CORS options
const corsOptions = {
    origin: [
        'https://glucobites.org',
        'https://www.glucobites.org',
        'http://localhost:5173'
    ]
};
app.use(cors(corsOptions));
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

const s3Client = new S3Client({
    region: process.env.AWS_REGION
});
const S3_BUCKET_NAME = 'glucobites-hp-documents';

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 },
});

app.get('/api/reviews/public', async (req, res) => {
    try {
        // This SQL query joins the reviews and users tables to get all the needed info.
        const query = `
            SELECT 
                r.rating,
                r.reviewText,
                u.first_name,
                u.last_name,
                u.pfpUrl 
            FROM 
                reviews AS r
            JOIN 
                users AS u ON r.userID = u.userID
            WHERE 
                r.rating >= 4       -- Only show good reviews (4 stars and up)
            ORDER BY 
                r.createdAt DESC    -- Show the newest reviews first
            LIMIT 15;               -- Limit to 15 reviews
        `;

        const [reviews] = await pool.query(query);

        // Format the data into a clean structure for the website.
        const formattedReviews = reviews.map(review => ({
            rating: review.rating,
            quote: review.reviewText,
            name: `${review.first_name || ''} ${review.last_name ? review.last_name.substring(0, 1) + '.' : ''}`.trim(),
            pfpUrl: review.pfpUrl
        }));

        res.status(200).json(formattedReviews);

    } catch (error) {
        console.error('Error fetching public reviews:', error);
        res.status(500).json({ message: 'Failed to retrieve app reviews due to a server error.' });
    }
});     

// This endpoint is no longer used by the new frontend but is kept as requested.
app.post('/api/s3-presigned-url', async (req, res) => {
    try {
        const { fileName, fileType } = req.body;
        if (!fileName || !fileType) {
            return res.status(400).json({ message: 'fileName and fileType are required.' });
        }
        const key = `${crypto.randomBytes(16).toString('hex')}-${fileName}`;
        const command = new PutObjectCommand({ Bucket: S3_BUCKET_NAME, Key: key, ContentType: fileType });
        const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });
        res.json({ uploadUrl: signedUrl, key: key });
    } catch (error) {
        console.error('Error generating presigned URL:', error);
        res.status(500).json({ message: 'Could not generate upload URL.' });
    }
});

app.post('/api/register', upload.single('certificate'), async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const { email, password, firstName, lastName, userType, healthcareType } = req.body;
        const certificateFile = req.file;

        if (!email || !password || !firstName || !lastName || !userType) {
            return res.status(400).json({ message: 'All required fields must be provided.' });
        }
        if (userType === 'Healthcare Provider') {
            if (!healthcareType) return res.status(400).json({ message: 'Healthcare provider type is required.' });
            if (!certificateFile) return res.status(400).json({ message: 'A certification document is required.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const setPremium = (userType === 'Premium') ? 1 : 0;
        const setProvider = (userType === 'Healthcare Provider') ? 1 : 0;
        
        const premiumExpire = (userType === 'Premium')
            ? new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
            : null;
        
        await connection.beginTransaction();
        
        let documentUrl = null;
        if (setProvider === 1 && certificateFile) {
            
            const safeFolderName = `${firstName}-${lastName}`
                .toLowerCase()
                .replace(/\s+/g, '-')      
                .replace(/[^a-z0-9-]/g, ''); 

            const uniqueFileName = `${crypto.randomBytes(16).toString('hex')}-${certificateFile.originalname}`;
            
            const s3DocumentKey = `${safeFolderName}/${uniqueFileName}`;
            
            const s3Command = new PutObjectCommand({ 
                Bucket: S3_BUCKET_NAME, 
                Key: s3DocumentKey, 
                Body: certificateFile.buffer, 
                ContentType: certificateFile.mimetype 
            });
            await s3Client.send(s3Command);
            
            documentUrl = `https://${S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3DocumentKey}`;
        }
        
        const userSql = `
            INSERT INTO users (email, password, first_name, last_name, verification_token, token_expires_at, setPremium, premiumExpire, setProvider) 
            VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP() + INTERVAL 1 HOUR, ?, ?, ?)
        `;
        const userValues = [email, hashedPassword, firstName, lastName, verificationToken, setPremium, premiumExpire, setProvider];
        const [userResult] = await connection.query(userSql, userValues);
        const newUserId = userResult.insertId;
        
        if (setProvider === 1) {
            const hpSql = `INSERT INTO verifyHP (userID, provType, document) VALUES (?, ?, ?)`;
            await connection.query(hpSql, [newUserId, healthcareType, documentUrl]);
        }
        
        await connection.commit();
        
        const verificationLink = `https://glucobites.org/verify-email?token=${verificationToken}`;
        const mailOptions = {
            from: `"GlucoBites" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Welcome to GlucoBites! Please Verify Your Email',
            html: `
              <div style="background-color: #f8f9fa; padding: 40px; font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.1);">
                  <div style="background-color: #00BBFF; color: white; padding: 20px; text-align: center;">
                    <h1 style="margin: 0; font-size: 24px;">Welcome to GlucoBites!</h1>
                  </div>
                  <div style="padding: 30px;">
                    <h2 style="font-size: 20px; color: #333;">Hi ${firstName},</h2>
                    <p style="color: #555; line-height: 1.6;">
                      Thank you for registering. We're excited to have you on board.
                      To complete your setup and secure your account, please verify your email address by clicking the button below.
                    </p>
                    <div style="text-align: center; margin: 30px 0;">
                      <a href="${verificationLink}" 
                         style="background-color: #00BBFF; color: white; padding: 15px 25px; text-decoration: none; border-radius: 5px; font-size: 16px; font-weight: bold; display: inline-block;">
                        Verify My Email
                      </a>
                    </div>
                    <p style="color: #555; line-height: 1.6;">
                      This verification link is valid for one hour.
                    </p>
                    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;" />
                    <p style="font-size: 12px; color: #999; text-align: center;">
                      If you did not create this account, you can safely ignore this email.
                      <br/>
                      © 2025 GlucoBites. All rights reserved.
                    </p>
                  </div>
                </div>
              </div>
            `,
        };
        await transporter.sendMail(mailOptions);
        
        res.status(201).json({ message: 'User registered successfully! Please check your email for a verification link.' });

    } catch (error) {
        await connection.rollback();
        console.error('Registration error:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Email address is already registered.' });
        }
        res.status(500).json({ message: 'Server error during registration.' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/verify-email', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ message: 'Verification token is required.' });

        const findUserSql = "SELECT * FROM users WHERE verification_token = ? AND token_expires_at > UTC_TIMESTAMP()";
        const [rows] = await pool.query(findUserSql, [token]);

        if (rows.length === 0) {
            return res.status(400).json({ message: 'Invalid or expired verification token.' });
        }
        const user = rows[0];

        const updateUserSql = "UPDATE users SET is_verified = TRUE, verification_token = NULL, token_expires_at = NULL WHERE userID = ?";
        await pool.query(updateUserSql, [user.userID]);
        
        res.status(200).json({ message: 'Email verified successfully! You can now log in.' });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ message: 'Server error during email verification.' });
    }
});

app.post('/api/login', async (req, res) => {
    // ... (rest of the code is unchanged)
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });

        const findUserSql = "SELECT * FROM users WHERE email = ?";
        const [rows] = await pool.query(findUserSql, [email]);

        if (rows.length === 0) return res.status(401).json({ message: 'Invalid credentials.' });

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials.' });

        if (!user.is_verified) {
            return res.status(403).json({ message: 'Please verify your email address before logging in.' });
        }
        
        const accessToken = jwt.sign({ userId: user.userID }, process.env.JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: user.userID }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

        res.status(200).json({
            message: 'Login successful!',
            userId: user.userID,
            accessToken,
            refreshToken
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Backend server running on http://localhost:${PORT}`));