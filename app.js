const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const app = express();
 const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const secretKey = 'your_secret_key';
const ejs = require('ejs');
const pdf = require('html-pdf');
const fetch = require('node-fetch');
const FormData = require('form-data');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const path = require('path');
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Parse JSON bodies
const fs = require('fs');
app.use(express.json());
const { createProxyMiddleware } = require('http-proxy-middleware');
const Razorpay = require('razorpay');
const dotenv = require('dotenv');
dotenv.config();



// const { Storage } = require('@google-cloud/storage');
const port = process.env.PORT || 8052;






const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, '../frontend/src/uploads'),
   filename: (req, file, cb) => {
    // Use Date.now() to get a unique timestamp and append the original filename
    const uniqueSuffix = Date.now() + '-' + file.originalname;
    cb(null, file.fieldname + '-' + uniqueSuffix);
  }
});

const upload = multer({ storage: storage });


const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
   port: 587,
  //  port: process.env.PORT || 587,
   secure: false, // use TLS
  // port: process.env.PORT || 465,
  // secure: true,
  auth: {
    user: 'nupurgarg8792@gmail.com',
    pass: 'zaal owwv ivsn ctht'
  }
});
//verification of user email
function sendVerificationEmail(email, token) {
  const verificationLink = `http://localhost:3000/verifyemail/${token}`;
  const mailOptions = {
    from: 'nupurgarg8792@gmail.com',
    to: email,
    subject: 'Verify Your Email',
    html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`
  };
  transporter.sendMail(mailOptions, function(error, info) {
    if (error) {
      console.log('Error sending email:', error);
    } else {
      console.log('Verification email sent:', info.response);
    }
  });
}

//forgot password
function sendForgotPasswordEmail(email, token) {
  const verificationLink = `http://localhost:3000/reset-password/${token}`;
    const mailOptions = {
      from: 'nupurgarg8792@gmail.com',
      to: email,
      subject: 'Reset Your Password',
      html: `<p>Click <a href="${verificationLink}">here</a> to reset your password</p>`
    };
    transporter.sendMail(mailOptions, function(error, info) {
      if (error) {
        console.log('Error sending email:', error);
      } else {
        console.log('Reset Password email sent:', info.response);
      }
    });
  }
 
// Connect to the SQLite database
let db = new sqlite3.Database('./Db-data/judgments5.db', sqlite3.OPEN_READWRITE, (err) => {
  if (err) {
    console.error(err.message);
    throw err; // Stop further execution in this callback
  }
  
  console.log('Connected to the SQLite database.');
  // Promisified get method






  // Create the users table if it doesn't exist
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    name TEXT,
    lawyerType TEXT,
    experience TEXT,
    age TEXT,
    mobile TEXT UNIQUE,  
    hashed_password TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT 0,
    email_verification_token TEXT,
    resetPasswordToken TEXT,       
    resetPasswordExpires INTEGER    
  
  )`,
   (tableErr) => {
    if (tableErr) {
      console.error(tableErr.message);
      throw tableErr; // Stop further execution if there's an error
    }
    
    console.log('Table "users" ensured.');
  });
});


// Middleware for parsing JSON bodies and enabling CORS
app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  credentials: true
}));


// Authentication middleware
function authenticateJWT(req, res, next) {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (ex) {
    res.status(400).json({ error: 'Invalid token.' });
  } 
}

// for load balancer
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', './index.html'));
});



// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password, name, mobile, lawyerType, experience, age } = req.body;
    if (!username || !password || !name || !mobile || !lawyerType || !experience || !age ) {
      return res.status(400).json({ error: 'Name, mobile, email, lawyerType, experience, age and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const emailVerificationToken = crypto.randomBytes(20).toString('hex');

    db.run('INSERT INTO users (name, lawyerType, experience, age, mobile, username, hashed_password, email_verification_token) VALUES (?,?,?,?, ?, ?, ?, ?)', 
      [name, lawyerType, experience, age, mobile, username, hashedPassword, emailVerificationToken], function (err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        const userId = this.lastID;
        db.run('INSERT INTO wallets (user_id, balance) VALUES (?, ?)', [userId, 0], function(err) {
            if (err) {
                console.error('Error creating wallet:', err);
                // Optionally handle the error, maybe roll back user creation or notify an admin
                return res.status(500).json({ error: 'Failed to create wallet' });
            }
        sendVerificationEmail(username, emailVerificationToken);
        res.json({ message: 'Registration successful. Please check your email to verify your account.' });
      });
    }
    );

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
app.post('/wallet/add-funds', authenticateJWT, async (req, res) => {
  // Check if the user is admin
  if (!req.user.isAdmin) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const { userId, amount } = req.body;
  db.run('UPDATE wallets SET balance = balance + ? WHERE user_id = ?', [amount, userId], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Funds added successfully' });
  });
});

let razorpayInstance = new Razorpay({
  key_id: 'rzp_test_SJsbPFYVQOtlbi',   //process.env.RAZORPAY_KEY_ID
  key_secret: 'pde3ZbrQ0YLWOps0GUHhQktB',// process.env.RAZORPAY_KEY_SECRET
});
app.post('/wallet/transfer-to-bank', authenticateJWT, async (req, res) => {
  const { amount, accountNumber, accountName, ifsc } = req.body;
  const userId = req.user.id;

  // You might want to validate and convert the amount to the smallest currency unit, etc.
  const payoutAmount = amount * 100; // Convert to paise

  // Create the payout
  const payout = {
    // account_number: process.env.RAZORPAY_ACCOUNT_NUMBER,
    fund_account: {
      account_type: "bank_account",
      bank_account: {
        name: accountName,
        account_number: accountNumber,
        ifsc: ifsc,
      },
    },
    amount: payoutAmount,
    currency: "INR",
    mode: "IMPS", // Choose the appropriate transfer mode
    purpose: "payout",
    description: "Wallet payout"
  };

  try {
    const response = await razorpayInstance.payouts.create(payout);

    // Here, update the wallet balance in your database accordingly
    // Also, log this transaction in your wallet_transactions table

    res.json({ success: true, payout: response });
  } catch (error) {
    console.error('Payout Error:', error);
    res.status(500).json({ success: false, message: "Failed to initiate payout", error: error.message });
  }
});

app.get('/wallet/balance', authenticateJWT, (req, res) => {
  const userId = req.user.id; // Assuming the user's ID is stored in the JWT payload

  db.get('SELECT id, balance FROM wallets WHERE user_id = ?', [userId], (err, row) => {
      if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (!row) {
          return res.status(404).json({ error: 'Wallet not found' });
      }

      res.json({ balance: row.balance });
  });
});


// Email verification endpoint
app.get('/verifyemail/:token', (req, res) => {
  const { token } = req.params;

  db.run('UPDATE users SET is_verified = 1 WHERE email_verification_token = ?', [token], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }
    res.json({ message: 'Email verified successfully! Please log in.' });
  });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT id, username, hashed_password, is_verified FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    if (!user.is_verified) {
      return res.status(401).json({ error: 'Email not verified. Please verify your email.' });
    }

    const validPassword = await bcrypt.compare(password, user.hashed_password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, secretKey);
    res.json({ token });
  });
});

app.get('/profile', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  
  db.get('SELECT id,username, name, mobile, lawyerType, experience, age FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.json(user);
  });
});
app.patch('/profile/edit/update', authenticateJWT, (req, res) => {
  console.log(req.body); 
  const userId = req.user.id;
  const { name, mobile, lawyerType, experience, age } = req.body;

  // Ensure that at least one field is provided for update
  if (!name && !mobile && !lawyerType && !experience && !age) {
    return res.status(400).json({ error: 'At least one field must be provided for update' });
  }

  // Build the SET clause for the update query dynamically
  const updateFields = [];
  const updateValues = [];

  if (name) {
    updateFields.push('name = ?');
    updateValues.push(name);
  }
  if (mobile) {
    updateFields.push('mobile = ?');
    updateValues.push(mobile);
  }
  if (lawyerType) {
    updateFields.push('lawyerType = ?');
    updateValues.push(lawyerType);
  }
  if (experience) {
    updateFields.push('experience = ?');
    updateValues.push(experience);
  }
  if (age) {
    updateFields.push('age = ?');
    updateValues.push(age);
  }

  const updateQuery = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
  const updateParams = [...updateValues, userId];

  db.run(updateQuery, updateParams, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found or no changes made' });
    }

    return res.json({ message: 'Profile updated successfully' });
  });
});


// Endpoint to initiate password reset
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const token = crypto.randomBytes(20).toString('hex');
  const resetTokenExpires = Date.now() + 3600000; // 1 hour from now

  db.run('UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE username = ?', [token, resetTokenExpires, email], function(err) {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }

    // const resetLink = `http://localhost:3000/reset-password/${token}`;
    // Send email with resetLink here using your sendVerificationEmail function or similar
    sendForgotPasswordEmail(email,  token);

    res.json({ message: 'Password reset email sent' });
  });
});

// Endpoint to reset password
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  db.run('UPDATE users SET hashed_password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE resetPasswordToken = ? AND resetPasswordExpires > ?', 
    [hashedPassword, token, Date.now()], function(err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (this.changes === 0) {
        return res.status(400).json({ error: 'Invalid or expired token' });
      }

      res.json({ message: 'Password successfully reset' });
  });
});


// Protected route example
app.get('/protected-route', authenticateJWT, (req, res) => {
  res.json({ message: 'This is a protected route' });
});



// Endpoint to search in the database
app.get('/search', (req, res) => {
  const { searchTerm, category } = req.query;

  if (!searchTerm || !category) {
    return res.status(400).json({ error: "Missing searchTerm or category" });
  }

  let sql = '';
  const params = [`%${searchTerm}%`];

  switch (category) {
    case 'Advocate':
      sql = `SELECT * FROM judgments WHERE pet_adv LIKE ? OR res_adv LIKE ?`;
      params.push(`%${searchTerm}%`);
      break;
    case 'Judge':
      sql = `SELECT * FROM judgments WHERE judgement_by LIKE ?`;
      break;
    case 'case_no':
      sql = `SELECT * FROM judgments WHERE case_no LIKE ?`;
      break;
    default:
      return res.status(400).json({ error: "Invalid category" });
  }

  db.all(sql, params, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});



app.get('/suggestions', (req, res, next) => {
  const { searchTerm, category } = req.query;
  if (!searchTerm || !category) {
    return res.status(400).json({ error: "Missing searchTerm or category" });
  }

  const queryMap = {
    'Advocate': `SELECT DISTINCT pet_adv AS name FROM judgments WHERE pet_adv LIKE ? UNION SELECT DISTINCT res_adv AS name FROM judgments WHERE res_adv LIKE ? LIMIT 20`,
    'Judge': `SELECT DISTINCT judgement_by AS name FROM judgments WHERE judgement_by LIKE ? LIMIT 20`,
    'case_no': `SELECT DISTINCT case_no AS name FROM judgments WHERE case_no LIKE ? LIMIT 20`
  };

  const sql = queryMap[category];
  if (!sql) {
    return res.status(400).json({ error: "Invalid category" });
  }

  const params = category === 'Advocate' ? [`%${searchTerm}%`, `%${searchTerm}%`] : [`%${searchTerm}%`];

  db.all(sql, params, (err, rows) => {
    if (err) {
      return next(err);
    }
    const suggestions = rows.map(row => row.name);
    res.json(suggestions);
  });
});


//advocate form
app.post('/advocate', authenticateJWT, async (req, res) => {
  try {
    const { hearingCourt, advocateName } = req.body;
    const userId = req.user.id;

    if (!hearingCourt || !advocateName) {
      return res.status(400).json({ error: 'Hearing court and advocate name are required' });
    }

    db.run('INSERT INTO AdvocateForm (hearingCourt, advocateName, user_id) VALUES (?, ?, ?)', [hearingCourt, advocateName, userId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json({ message: 'Advocate form submitted successfully' });
    });
  } catch (error) {
    console.log(error);
  }
});
  
// Retrieve advocate forms for the authenticated user
app.get('/advocate', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  
  db.all('SELECT * FROM AdvocateForm WHERE user_id = ?', [userId], (err, forms) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json(forms);
  });
});

// after proxy form
app.post('/afterproxy', authenticateJWT, async (req, res) => {
  try {
    const { contactMethod, contactInfo } = req.body;
    const userId = req.user.id;

    if (!contactMethod) {
      return res.status(400).json({ error: 'Contact method is required' });
    }

    db.run('INSERT INTO AfterProxyForm (contactMethod, contactInfo, user_id) VALUES (?, ?, ?)', [contactMethod, contactInfo, userId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json({ message: 'After Proxy form submitted successfully' });
    });
  } catch (error) {
    console.log(error);
  }
});
app.get('/alerts', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  db.all('SELECT id,title, startDate, completionDate, assignTo FROM AlertsForm WHERE user_id = ?', [userId], (err, forms) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json(forms);
  });
});
//get endpoint to render data on edit form
app.get('/alerts/edit', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT id, title, startDate, completionDate, caseTitle, caseType, assignFrom, assignTo FROM AlertsForm WHERE user_id = ?',
    [userId],
    (err, alertForms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(alertForms);
    }
  );
});

//update endpoint to update the render data on edit form
app.put('/alerts/edit/update/:alertId', authenticateJWT, (req, res) => {
  const alertId = req.params.alertId;
  const userId = req.user.id;
  const { title, startDate, completionDate, caseTitle, caseType, assignFrom, assignTo } = req.body;

  const checkQuery = 'SELECT * FROM AlertsForm WHERE title = ? AND id != ? AND user_id = ?';
  
  db.get(checkQuery, [title, alertId, userId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (row) {
      return res.status(400).json({ error: 'Title already exists, please change your Title' });
    }

    const updateQuery = 'UPDATE AlertsForm SET title = ?, startDate = ?, completionDate = ?, caseTitle = ?, caseType = ?, assignFrom = ?, assignTo = ? WHERE id = ? AND user_id = ?';
    
    db.run(updateQuery, [title, startDate, completionDate, caseTitle, caseType, assignFrom, assignTo, alertId, userId], (updateErr) => {
      if (updateErr) {
        return res.status(500).json({ error: updateErr.message });
      }
      res.json({ message: 'Alert form updated successfully' });
    });
  });
});



// alerts forms
app.post('/alerts', authenticateJWT, async (req, res) => {
  try {
    const { title, startDate, completionDate, assignFrom, assignTo, caseTitle, caseType } = req.body;
    const userId = req.user.id;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    // Check if title is already in use
    db.get('SELECT * FROM AlertsForm WHERE title = ?', [title], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (row) {
        return res.status(400).json({ error: 'Task with this title already exists, Please change the Title' });
      }

      // Proceed to insert the new record
      db.run(
        'INSERT INTO AlertsForm (title, startDate, completionDate, assignFrom, assignTo, caseTitle, caseType, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [title, startDate, completionDate, assignFrom, assignTo, caseTitle, caseType, userId],
        function (insertErr) {
          if (insertErr) {
            return res.status(500).json({ error: insertErr.message });
          }
          return res.json({ message: 'Alerts form submitted successfully' });
        }
      );
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/hearings', authenticateJWT, (req, res) => {
  try {
    const { title, assignedLawyer, status, caseTitle, hearingDate, startTime, endTime } = req.body;
    const userId = req.user.id;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    // Check if title is already in use
    db.get('SELECT * FROM CourtHearing WHERE title = ?', [title], (findErr, row) => {
      if (findErr) {
        console.error(findErr);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (row) {
        return res.status(400).json({ error: 'A hearing with this title already exists. Please use a different title.' });
      }

      // Proceed to insert the new record
      db.run(
        'INSERT INTO CourtHearing (title, assignedLawyer, status, caseTitle, hearingDate, startTime, endTime, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [title, assignedLawyer, status, caseTitle, hearingDate, startTime, endTime, userId],
        function (err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          return res.json({ message: 'Hearing form submitted successfully' });
        }
      );
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/appointments', authenticateJWT, (req, res) => {
  try {
    const {title, caseTitle, caseType, appointmentDate, contactPerson, location, startTime, endTime, email} = req.body;
    const userId = req.user.id;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    // Check if an appointment with the same title already exists
    db.get('SELECT * FROM Appointments WHERE title = ?', [title], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (row) {
        return res.status(400).json({ error: 'An appointment with this title already exists. Please use a different title.' });
      }

      // Proceed to insert the new appointment
      db.run(
        'INSERT INTO Appointments (title, caseTitle, caseType, appointmentDate, contactPerson, location, startTime, endTime, email, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [title, caseTitle, caseType, appointmentDate, contactPerson, location, startTime, endTime, email, userId],
        function (insertErr) {
          if (insertErr) {
            return res.status(500).json({ error: insertErr.message });
          }
          return res.json({ message: 'Appointment added successfully' });
        }
      );
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get("/calendar/alerts", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    "SELECT id, title, startDate, completionDate, assignTo, caseTitle, caseType FROM AlertsForm WHERE user_id = ?",
    [userId],
    (err, forms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(forms);
    }
  );
});

app.get("/calendar/hearings", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    "SELECT id, title, assignedLawyer, status, hearingDate, caseTitle, startTime, endTime FROM CourtHearing WHERE user_id = ?",
    [userId],
    (err, forms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(forms);
    }
  );
});

app.get("/calendar/appointments", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    "SELECT id, title, caseTitle, caseType, appointmentDate, contactPerson, location, startTime, endTime, email FROM Appointments WHERE user_id = ?",
    [userId],
    (err, forms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(forms);
    }
  );
});



app.get('/calendar/alerts/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;

  db.get(
    'SELECT id, title, startDate, completionDate, caseTitle, caseType, assignFrom, assignTo FROM AlertsForm WHERE id = ? AND user_id = ?',
    [taskId, userId],
    (err, event) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!event) {
        return res.status(404).json({ message: 'Event not found' });
      }

      res.json(event);
    }
  );
});

app.get('/calendar/hearings/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;

  db.get(
    'SELECT id, title, assignedLawyer, status, hearingDate, caseTitle, startTime, endTime FROM CourtHearing WHERE id = ? AND user_id = ?',
    [taskId, userId],
    (err, event) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!event) {
        return res.status(404).json({ message: 'Event not found' });
      }

      res.json(event);
    }
  );
});

app.get('/calendar/appointments/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;

  db.get(
    'SELECT id, title, caseTitle, caseType,  appointmentDate, contactPerson, location, startTime, endTime, email FROM Appointments WHERE id = ? AND user_id = ?',
    [taskId, userId],
    (err, event) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!event) {
        return res.status(404).json({ message: 'Event not found' });
      }

      res.json(event);
    }
  );
});

// Update a specific task event by ID
app.put('/calendar/alerts/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;
  const { title, startDate, completionDate, caseTitle, caseType, assignFrom, assignTo } = req.body;

  db.run(
    'UPDATE AlertsForm SET title = ?, startDate = ?, completionDate = ?, caseTitle = ?, caseType = ?, assignFrom = ?, assignTo = ? WHERE id = ? AND user_id = ?',
    [title, startDate, completionDate, caseTitle, caseType, assignFrom, assignTo, taskId, userId],
    (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({ message: 'Event updated successfully' });
    }
  );
});

app.put('/calendar/hearings/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;
  const { title, assignedLawyer, status, caseTitle, hearingDate, startTime, endTime } = req.body;

  // First, check if there is any other hearing with the same title
  db.get('SELECT id FROM CourtHearing WHERE title = ? AND id != ?', [title, taskId], (findErr, row) => {
    if (findErr) {
      console.error(findErr);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    // If another hearing with the same title exists, prevent update
    if (row) {
      return res.status(400).json({ error: 'A hearing with this title already exists. Please use a different title.' });
    }

    // Proceed with the update if the title is unique
    db.run(
      'UPDATE CourtHearing SET title = ?, assignedLawyer = ?, status = ?, hearingDate = ?, caseTitle = ?, startTime = ?, endTime = ? WHERE id = ? AND user_id = ?',
      [title, assignedLawyer, status, hearingDate, caseTitle, startTime, endTime, taskId, userId],
      (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        res.json({ message: 'Event updated successfully' });
      }
    );
  });
});

app.put('/calendar/appointments/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;
  const { title, caseTitle, caseType, appointmentDate, contactPerson, location, startTime, endTime, email } = req.body;

  // First, check if there is any other appointment with the same title
  db.get('SELECT id FROM Appointments WHERE title = ? AND id != ?', [title, taskId], (findErr, row) => {
    if (findErr) {
      console.error(findErr);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    // If another appointment with the same title exists, prevent update
    if (row) {
      return res.status(400).json({ error: 'An appointment with this title already exists. Please use a different title.' });
    }

    // Proceed with the update if the title is unique
    db.run(
      'UPDATE Appointments SET title = ?, caseTitle = ?, caseType = ?, appointmentDate = ?, contactPerson = ?, location = ?, startTime = ?, endTime = ?, email = ? WHERE id = ? AND user_id = ?',
      [title, caseTitle, caseType, appointmentDate, contactPerson, location, startTime, endTime, email, taskId, userId],
      (err) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        res.json({ message: 'Event updated successfully' });
      }
    );
  });
});


// Delete a specific task event by ID
app.delete('/calendar/alerts/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;

  db.run('DELETE FROM AlertsForm WHERE id = ? AND user_id = ?', [taskId, userId], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    res.json({ message: 'Event deleted successfully' });
  });
});

app.delete('/calendar/hearings/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;

  db.run('DELETE FROM CourtHearing WHERE id = ? AND user_id = ?', [taskId, userId], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    res.json({ message: 'Event deleted successfully' });
  });
});

app.delete('/calendar/appointments/:taskId', authenticateJWT, (req, res) => {
  const taskId = req.params.taskId;
  const userId = req.user.id;

  db.run('DELETE FROM Appointments WHERE id = ? AND user_id = ?', [taskId, userId], (err) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    res.json({ message: 'Event deleted successfully' });
  });
});

// Delete alert by ID
app.delete('/alerts/:alertId', authenticateJWT, async (req, res) => {
  try {
    const { alertId } = req.params;

    // Check if the alert with the given ID belongs to the authenticated user
    const alertExists = await db.get(
      'SELECT id FROM AlertsForm WHERE id = ? AND user_id = ?',
      [alertId, req.user.id]
    );

    if (!alertExists) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    // Delete the alert with the given ID
    await db.run('DELETE FROM AlertsForm WHERE id = ?', [alertId]);

    return res.json({ message: 'Alert deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Download alert PDF by ID
app.get('/alerts/download-pdf/:alertId', authenticateJWT, async (req, res) => {
  try {
    const { alertId } = req.params;

    // Check if the alert with the given ID belongs to the authenticated user
    const alertData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM AlertsForm WHERE id = ? AND user_id = ?',
        [alertId, req.user.id],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });

    if (!alertData) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    // Define an HTML template for your PDF content (you can use a template engine like EJS)
    const template = `
    <html>
    <head>
      <title>Alert Data</title>
      <style>
      
    </style>
    </head>
    <body>
      <h1>Alert Data</h1>
      <p>Title: <%= title %></p>
      <p>Case Title: <%= caseTitle %></p>
      <p>Case Type: <%= caseType %></p>
      <p>Start Date: <%= startDate %></p>
      <p>Completion Date: <%= completionDate %></p>
      <p>Assign From: <%= assignFrom %></p>
      <p>Assign To: <%= assignTo %></p>
      
      
      
      <!-- Add more fields as needed -->
    </body>
  </html>
  
    `;

    // Compile the template with data
    const htmlContent = ejs.render(template, alertData);

    // Create a PDF from the HTML content
    pdf.create(htmlContent).toStream((err, stream) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error generating PDF' });
      }

      // Set the response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=Alert_${alertData.id}.pdf`);

      // Pipe the PDF stream to the response
      stream.pipe(res);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});





// endpoint = fetch in alert form only!
app.get('/dashboard/alert/teammembers', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    
    db.all(
      'SELECT fullName AS name FROM TeamMembers WHERE user_id = ? ' +
      'UNION ' +
      'SELECT firstName || " " || lastName AS name FROM ClientForm WHERE user_id = ?',
      [userId, userId],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        return res.json(result);
      }
    );
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


//get endpoint to render teammember form data on edit form
app.use('/uploads', express.static(path.join(__dirname, '../frontend/src/uploads')));


//get endpoint to render teammember form data on edit form
app.get('/dashboard/teammemberform/edit', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT id,image, fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno FROM TeamMembers WHERE user_id = ?',
    [userId],
    (err, teamMembers) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(teamMembers);
    }
  );
});

//update endpoint to update the render data on edit form
app.put('/dashboard/teammemberform/edit/update/:memberId', authenticateJWT, (req, res) => {
  const memberId = req.params.memberId;
  const userId = req.user.id;
  const imagePath = req.body.image || null;
    console.log("Image Path:", imagePath);
  const {
    fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno
  } = req.body;

  // Check if email or mobileNo is already in use by another record
  const checkQuery = `SELECT * FROM TeamMembers WHERE (email = ? OR mobileno = ?) AND id != ?`;
  db.get(checkQuery, [email, mobileno, memberId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (row) {
      if (row.email === email && row.mobileno === mobileno) {
        return res.status(400).json({ error: 'Please enter a unique email and mobile number' });
      } else if (row.email === email) {
        return res.status(400).json({ error: 'Please enter a unique email' });
      } else if (row.mobileno === mobileno) {
        return res.status(400).json({ error: 'Please enter a unique mobile number' });
      }
    }

    // Proceed to update the record
    const updateQuery = `
      UPDATE TeamMembers SET  image = COALESCE(?, image),fullName = ?, email = ?, designation = ?, address = ?, state = ?, city = ?, zipCode = ?, selectedGroup = ?, selectedCompany = ?, mobileno = ? 
      WHERE id = ? AND user_id = ?
    `;
    db.run(updateQuery, [imagePath,fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno, memberId, userId], (updateErr) => {
      if (updateErr) {
        console.error(updateErr);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ message: 'Team member updated successfully' });
    });
  });
});


app.post('/upload', upload.single('image'), (req, res) => {
  if (req.file) {
    // Store only the filename
    const filename = req.file.filename; // Adjust this line to get only the filename
    res.json({ imagePath: filename });
  } else {
    res.status(400).json({ error: 'No file uploaded.' });
  }
});

//Team Members form endpoints
app.post("/dashboard/teammemberform", authenticateJWT, async (req, res) => {
 
  console.log(req.body);
  try {
    const imagePath = req.body.image || null;
    console.log("Image Path:", imagePath);

    const {
       fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno
    } = req.body;
    const userId = req.user.id;

    // Check if email or mobileNo is already in use
    const checkQuery = `SELECT * FROM TeamMembers WHERE email = ? OR mobileno = ?`;
    db.get(checkQuery, [email, mobileno], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (row) {
        if (row.email === email && row.mobileno === mobileno) {
          return res.status(400).json({ error: 'Please enter a unique email and mobile number' });
        } else if (row.email === email) {
          return res.status(400).json({ error: 'Please enter a unique email' });
        } else if (row.mobileno === mobileno) {
          return res.status(400).json({ error: 'Please enter a unique mobile number' });
        }
      }

      // Proceed to insert the new record
      const insertQuery = `
        INSERT INTO TeamMembers (image, fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno, user_id) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      db.run(insertQuery, [imagePath, fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno, userId], function(insertErr) {
        if (insertErr) {
          console.error(insertErr);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        return res.json({ message: 'Team member added successfully' });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.post("/dashboard/teammemberform/companyform", authenticateJWT, async (req, res) => {
  try {
    const {
      companyName,
      person,
      email,
      contactNumber,
      websiteLink,
      address,
    } = req.body;
    
    const userId = req.user.id;

    // Insert data into the Companies table
    db.run(
      'INSERT INTO Companies (companyName, person, email, contactNumber, websiteLink, address, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [companyName, person, email, contactNumber, websiteLink, address, userId],
      function (err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        return res.json({ message: "Company added successfully" });
      }
    );
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.get('/dashboard/teammemberform', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all('SELECT id,fullName, email, designation,selectedGroup FROM TeamMembers WHERE user_id = ?', [userId], (err, forms) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json(forms);
  });
});
app.delete('/dashboard/teammemberform/:memberId', authenticateJWT, async (req, res) => {
  try {
    const { memberId } = req.params;

    // Check if the team member with the given ID belongs to the authenticated user
    const memberExists = await db.get(
      'SELECT id FROM TeamMembers WHERE id = ? AND user_id = ?',
      [memberId, req.user.id]
    );

    if (!memberExists) {
      return res.status(404).json({ error: 'Team member not found' });
    }

    // Delete the team member with the given ID
    await db.run('DELETE FROM TeamMembers WHERE id = ?', [memberId]);

    return res.json({ message: 'Team member deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/dashboard/teammemberform/download-pdf/:memberId', authenticateJWT, async (req, res) => {
  try {
    const { memberId } = req.params;

    // Check if the team member with the given ID belongs to the authenticated user
    const memberData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM TeamMembers WHERE id = ? AND user_id = ?',
        [memberId, req.user.id],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });

    if (!memberData) {
      return res.status(404).json({ error: 'Team member not found' });
    }

    // Define an HTML template for your PDF content (you can use a template engine like EJS)
    const template = `
    <html>
    <head>
      <title>Team Member Data</title>
    </head>
    <body>
      <h1>Team Member Data</h1>
      <p>Full Name: <%= fullName %></p>
      <p>Email: <%= email %></p>
      <p>Mobile Number: <%= mobileno %></p>
      <p>Designation: <%= designation %></p>
      <p>Address: <%= address %></p>
      <p>State: <%= state %></p>
      <p>City: <%= city %></p>
      <p>Zip Code: <%= zipCode %></p>
      <p>Selected Group: <%= selectedGroup %></p>
    </body>
  </html>
    `;

    // Compile the template with data
    const htmlContent = ejs.render(template, memberData);

    // Create a PDF from the HTML content
    pdf.create(htmlContent).toStream((err, stream) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error generating PDF' });
      }

      // Set the response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=TeamMember_${memberData.id}.pdf`);

      // Pipe the PDF stream to the response
      stream.pipe(res);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});




app.get('/dashboard/groupform', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT groupName FROM GroupForm WHERE user_id = ?', [userId], (err, groupName) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(groupName);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});





//appointmentForm
app.post('/appointment', authenticateJWT, async (req, res) => {
  try {
    const {
      title,client,email,mobile,date,time,roomNo,assignedBy,assignedTo,followUpDate,followUpTime,description,} = req.body;

    const userId = req.user.id;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    db.run(
      'INSERT INTO AppointmentForm (title, client, email, mobile, date, time, roomNo, assignedBy, assignedTo, followUpDate, followUpTime, description, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        title,client,email,mobile,date,time,roomNo,assignedBy,assignedTo,followUpDate,followUpTime,description,userId,
      ],
      function (err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        return res.json({ message: 'Appointment form submitted successfully' });
      }
    );
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/dashboard/clientform', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT firstName FROM ClientForm WHERE user_id = ?', [userId], (err, firstName) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(firstName);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


//get endpoint to render bill data when edit button is clicked on show bill
app.get('/bill/edit', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT id, billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc FROM BillForm WHERE user_id = ?',
    [userId],
    (err, billForms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(billForms);
    }
  );
});

//update endpoint to update the render data when edit button is clicked on show bill
app.put('/bill/edit/update/:billId', authenticateJWT, (req, res) => {
  const billId = req.params.billId;
  const userId = req.user.id;
  const {
    billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc
  } = req.body;

  db.run(
    'UPDATE BillForm SET billNumber = ?, title = ?, currentDate = ?, dateFrom = ?, dateTo = ?, fullAddress = ?, billingType = ?, totalHours = ?, noOfHearings = ?, totalAmount = ?, amount = ?, taxType = ?, taxPercentage = ?, totalAmountWithTax = ?, description = ?, addDoc = ? WHERE id = ? AND user_id = ?',
    [billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc, billId, userId],
    (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({ message: 'Bill form updated successfully' });
    }
  );
});



app.post('/uploaddocbill', upload.single('addDoc'), (req, res) => {
  if (req.file) {
    const filename = req.file.filename; // Adjust this line to get only the filename
    res.json({ filePath: filename });
  } else {
    res.status(400).json({ error: 'No file uploaded.' });
  }
});
// POST Endpoint for Submitting Bill Form
app.post('/bill', authenticateJWT, async (req, res) => {
  try {
    const {
      billNumber,title,currentDate,dateFrom,dateTo,fullAddress,billingType,totalHours,noOfHearings,totalAmount,amount,taxType,taxPercentage,totalAmountWithTax,description,addDoc} = req.body;

    const userId = req.user.id;

    if (!billNumber || !title) {
      return res.status(400).json({ error: 'Bill number and title are required' });
    }
    db.run(
      'INSERT INTO BillForm (billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        billNumber,title,currentDate,dateFrom,dateTo,fullAddress,billingType, totalHours,noOfHearings,totalAmount,amount,taxType,taxPercentage,totalAmountWithTax,description,addDoc,userId,
      ],
      function (err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        return res.json({ message: 'Bill form submitted successfully' });
      }
    );
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/billdata', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  db.all('SELECT id,billNumber, title, dateFrom, dateTo, amount, totalAmountWithTax FROM BillForm WHERE user_id = ?', [userId], (err, forms) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json(forms);
  });
});
app.delete('/billdata/:billId', authenticateJWT, async (req, res) => {
  try {
    const { billId } = req.params;

    // Check if the bill with the given ID belongs to the authenticated user
    const billExists = await db.get(
      'SELECT id FROM BillForm WHERE id = ? AND user_id = ?',
      [billId, req.user.id]
    );

    if (!billExists) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    // Delete the bill with the given ID
    await db.run('DELETE FROM BillForm WHERE id = ?', [billId]);

    return res.json({ message: 'Bill deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Download bill PDF by ID
app.get('/billdata/download-pdf/:billId', authenticateJWT, async (req, res) => {
  try {
    const { billId } = req.params;

    // Check if the bill with the given ID belongs to the authenticated user
    const billData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM BillForm WHERE id = ? AND user_id = ?',
        [billId, req.user.id],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });

    if (!billData) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    // Define an HTML template for your PDF content (you can use a template engine like EJS)
    const template = `
    <html>
  <head>
    <title>Bill Data</title>
  </head>
  <body>
    <h1>Bill Data</h1>
    <p>Bill Number: <%= billNumber %></p>
    <p>Title: <%= title %></p>
    <p>Current Date: <%= currentDate %></p>
    <p>Date From: <%= dateFrom %></p>
    <p>Date To: <%= dateTo %></p>
    <p>Full Address: <%= fullAddress %></p>
    <p>Billing Type: <%= billingType %></p>
    <p>Total Hours: <%= totalHours %></p>
    <p>No. of Hearings: <%= noOfHearings %></p>
    <p>Total Amount: <%= totalAmount %></p>
    <p>Amount: <%= amount %></p>
    <p>Tax Type: <%= taxType %></p>
    <p>Tax Percentage: <%= taxPercentage %></p>
    <p>Total Amount With Tax: <%= totalAmountWithTax %></p>
    <p>Description: <%= description %></p>
    <!-- Add more fields as needed -->
  </body>
</html>

    `;

    // Compile the template with data
    const htmlContent = ejs.render(template, billData);

    // Create a PDF from the HTML content
    pdf.create(htmlContent).toStream((err, stream) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error generating PDF' });
      }

      // Set the response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=Bill_${billData.id}.pdf`);

      // Pipe the PDF stream to the response
      stream.pipe(res);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});




app.post('/updatecase', authenticateJWT, async (req, res) => {
  try {
    const casesArray = req.body.cases; // Extracting the array of cases from the request body
    const userId = req.user.id; // Extracting the user ID from the authenticated user

    // SQL query template for inserting a case
    const query = `INSERT INTO UpdateCases (
      cino, case_no, court_no_desg_name, date_last_list, date_next_list, 
      date_of_decision, district_code, district_name, establishment_code, 
      establishment_name, fil_no, fil_year, lcourt_no_desg_name, ldistrict_name, 
      lestablishment_name, lpetparty_name, lresparty_name, lstate_name, ltype_name, 
      petparty_name, note, reg_no, reg_year, resparty_name, 
      state_code, state_name, type_name, updated, user_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    // Loop over each case object and insert into the database
    for (const caseData of casesArray) {
      db.run(
        query,
        [
          caseData.cino, caseData.case_no, caseData.court_no_desg_name, caseData.date_last_list, caseData.date_next_list,
          caseData.date_of_decision, caseData.district_code, caseData.district_name, caseData.establishment_code,
          caseData.establishment_name, caseData.fil_no, caseData.fil_year, caseData.lcourt_no_desg_name, caseData.ldistrict_name,
          caseData.lestablishment_name, caseData.lpetparty_name, caseData.lresparty_name, caseData.lstate_name, caseData.ltype_name,
          caseData.petparty_name, caseData.note, caseData.reg_no, caseData.reg_year, caseData.resparty_name,
          caseData.state_code, caseData.state_name, caseData.type_name, caseData.updated, userId
        ],
        function (err) {
          if (err) {
            console.error('Error inserting case:', err.message);
            // Handle error - perhaps accumulate errors in a list and return them later
          }
          // Successful insert for this case
        }
      );
    }

    // Respond to the client after all cases have been processed
    res.json({ message: 'All cases submitted successfully' });

  } catch (error) {
    console.error('Error in /updatecase endpoint:', error.message);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.get("/edit/updatecases", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    "SELECT id,title, cino, case_no, court_no_desg_name, date_last_list, date_next_list, date_of_decision, district_code, district_name, establishment_code, establishment_name, fil_no, fil_year, lcourt_no_desg_name, ldistrict_name, lestablishment_name, lpetparty_name, lresparty_name, lstate_name, ltype_name, petparty_name, note, reg_no, reg_year, resparty_name, state_code, state_name, type_name, updated FROM UpdateCases WHERE user_id = ?",
    [userId],
    (err, updateCases) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(updateCases);
    }
  );
});

app.get("/edit/updatecases/:caseId", authenticateJWT, (req, res) => {
  const userId = req.user.id;
  const caseId = req.params.caseId;

  db.get(
    "SELECT * FROM UpdateCases WHERE user_id = ? AND id = ?",
    [userId, caseId],
    (err, updateCase) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (updateCase) {
        return res.json(updateCase);
      } else {
        return res.status(404).json({ error: "Case not found" });
      }
    }
  );
});


app.delete('/dashboard/updatecases/:caseId', authenticateJWT, async (req, res) => {
  try {
    const { caseId } = req.params;
    const userId = req.user.id;

    // Check if the case with the given ID belongs to the authenticated user
    const caseExists = await db.get(
      'SELECT id FROM UpdateCases WHERE id = ? AND user_id = ?',
      [caseId, userId]
    );

    if (!caseExists) {
      return res.status(404).json({ error: 'Case not found' });
    }

    // Delete the case with the given ID
    await db.run('DELETE FROM UpdateCases WHERE id = ?', [caseId]);

    return res.json({ message: 'Case deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/dashboard/updatecases/download-pdf/:caseId', authenticateJWT, async (req, res) => {
  try {
    const { caseId } = req.params;
    const userId = req.user.id;
    // Check if the case with the given ID belongs to the authenticated user
    const caseData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM UpdateCases WHERE id = ? AND user_id = ?',
        [caseId, userId],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });

    if (!caseData) {
      return res.status(404).json({ error: 'Case not found' });
    }

    // Define an HTML template for your PDF content
    // Note: Update the fields according to the UpdateCases table structure
    const template = `
    <html>
    <head>
      <title>Update Case Data</title>
    </head>
    <body>
      <h1>Update Case Data</h1>
      
      <p>Title: <%= title %></p>
      <p>CNR NO: <%= cino %></p>
      <p>Case No: <%= case_no %></p>
      <p>Court No/Designation Name: <%= court_no_desg_name %></p>
      <p>Date Last Listed: <%= date_last_list %></p>
      <p>Date Next Listed: <%= date_next_list %></p>
      <p>Date of Decision: <%= date_of_decision %></p>
      <p>District Code: <%= district_code %></p>
      <p>District Name: <%= district_name %></p>
      <p>Establishment Code: <%= establishment_code %></p>
      <p>Establishment Name: <%= establishment_name %></p>
      <p>Filing No: <%= fil_no %></p>
      <p>Filing Year: <%= fil_year %></p>
      <p>Linked Court No/Designation Name: <%= lcourt_no_desg_name %></p>
      <p>Linked District Name: <%= ldistrict_name %></p>
      <p>Linked Establishment Name: <%= lestablishment_name %></p>
      <p>Linked Petparty Name: <%= lpetparty_name %></p>
      <p>Linked Resparty Name: <%= lresparty_name %></p>
      <p>Linked State Name: <%= lstate_name %></p>
      <p>Linked Type Name: <%= ltype_name %></p>
      <p>Petparty Name: <%= petparty_name %></p>
      <p>Note: <%= note %></p>
      <p>Registration No: <%= reg_no %></p>
      <p>Registration Year: <%= reg_year %></p>
      <p>Resparty Name: <%= resparty_name %></p>
      <p>State Code: <%= state_code %></p>
      <p>State Name: <%= state_name %></p>
      <p>Type Name: <%= type_name %></p>
      <p>Updated: <%= updated %></p>
    </body>
  </html>
  
    `;

    // Compile the template with data
    const htmlContent = ejs.render(template, caseData);

    // Create a PDF from the HTML content
    pdf.create(htmlContent).toStream((err, stream) => {
      if (err) {
        return res.status(500).json({ error: 'Error generating PDF' });
      }

      // Set the response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=UpdateCase_${caseData.id}.pdf`);

      // Pipe the PDF stream to the response
      stream.pipe(res);
    });
  } catch (error) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/edit/updatecases/update/:caseId', authenticateJWT, (req, res) => {
  const caseId = req.params.caseId;
  const userId = req.user.id;
  const {
    cino, case_no, court_no_desg_name, date_last_list, date_next_list,
    date_of_decision, district_code, district_name, establishment_code,
    establishment_name, fil_no, fil_year, lcourt_no_desg_name, ldistrict_name,
    lestablishment_name, lpetparty_name, lresparty_name, lstate_name,
    ltype_name, petparty_name, note, reg_no, reg_year, resparty_name,
    state_code, state_name, type_name, updated
  } = req.body;

  // Update the case in the UpdateCases table
  db.run(
    'UPDATE UpdateCases SET cino = ?, case_no = ?, court_no_desg_name = ?, date_last_list = ?, date_next_list = ?, date_of_decision = ?, district_code = ?, district_name = ?, establishment_code = ?, establishment_name = ?, fil_no = ?, fil_year = ?, lcourt_no_desg_name = ?, ldistrict_name = ?, lestablishment_name = ?, lpetparty_name = ?, lresparty_name = ?, lstate_name = ?, ltype_name = ?, petparty_name = ?, note = ?, reg_no = ?, reg_year = ?, resparty_name = ?, state_code = ?, state_name = ?, type_name = ?, updated = ?  WHERE id = ? AND user_id = ?',
    [cino, case_no, court_no_desg_name, date_last_list, date_next_list, date_of_decision, district_code, district_name, establishment_code, establishment_name, fil_no, fil_year, lcourt_no_desg_name, ldistrict_name, lestablishment_name, lpetparty_name, lresparty_name, lstate_name, ltype_name, petparty_name, note, reg_no, reg_year, resparty_name, state_code, state_name, type_name, updated, caseId, userId],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ message: 'Case updated successfully' });
    }
  );
});









// get endpoint to show a case so the user can edit it 
app.get("/edit/caseform", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    "SELECT id, title, caseType, courtType, courtName, caveatNo, caseCode, caseURL, caseStatus, honorableJudge, courtHallNo, cnrNo, batchNo, dateOfFiling, practiceArea, manage, client, team,type,lawyerType, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId FROM CasesForm WHERE user_id = ?",
    [userId],
    (err, forms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(forms);
    }
  );
});
// get endpoint to update the case so the user can edit it 
app.put('/edit/caseform/update/:caseId', authenticateJWT, (req, res) => {
  const caseId = req.params.caseId;
  const userId = req.user.id;
  const {
    title, caseType, courtType, courtName, caveatNo, caseCode, caseURL, 
    caseStatus, honorableJudge, courtHallNo, cnrNo, batchNo, dateOfFiling,
    practiceArea, manage, client, team, type, lawyerType, 
    clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId
  } = req.body;

  // First, check if another case with the same title exists (excluding the current case)
  db.get(
    'SELECT id FROM CasesForm WHERE title = ? AND id != ?',
    [title, caseId],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (row) {
        // If another case with the same title exists
        return res.status(400).json({ error: 'This title is already in use, please choose a different title' });
      }

      // If the title is unique, proceed with updating the case
      db.run(
        'UPDATE CasesForm SET title = ?, caseType = ?, courtType = ?, courtName = ?, caveatNo = ?, caseCode = ?, caseURL = ?, caseStatus = ?, honorableJudge = ?, courtHallNo = ?, cnrNo = ?, batchNo = ?, dateOfFiling = ?, practiceArea = ?, manage = ?, client = ?, team = ?, type = ?, lawyerType = ?, clientDesignation = ?, opponentPartyName = ?, lawyerName = ?, mobileNo = ?, emailId = ? WHERE id = ? AND user_id = ?',
        [title, caseType, courtType, courtName, caveatNo, caseCode, caseURL, caseStatus, honorableJudge, courtHallNo, cnrNo, batchNo, dateOfFiling, practiceArea, manage, client, team, type, lawyerType, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId, caseId, userId],
        (updateErr) => {
          if (updateErr) {
            console.error(updateErr);
            return res.status(500).json({ error: updateErr.message });
          }
          res.json({ message: 'Case updated successfully' });
        }
      );
    }
  );
});





// POST endpoint to add a new case form
app.post('/caseform', authenticateJWT, async (req, res) => {
  try {
    const {
      title, caseType, courtType, courtName, caveatNo, caseCode, caseURL, 
      caseStatus, honorableJudge, courtHallNo, cnrNo, batchNo, dateOfFiling, practiceArea, manage
    } = req.body;

    const userId = req.user.id;

    // Check if the title already exists
    db.get("SELECT id FROM CasesForm WHERE title = ?", [title], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (row) {
        return res.status(400).json({ error: 'This title is already in our database, please add some other title' });
      }

      // Insert query for adding a new case
      const insertQuery = `
        INSERT INTO CasesForm (
          title, caseType, courtType, courtName, caveatNo, caseCode, caseURL, caseStatus,
          honorableJudge, courtHallNo, cnrNo, batchNo, dateOfFiling, practiceArea, manage, user_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      db.run(
        insertQuery,
        [title, caseType, courtType, courtName, caveatNo, caseCode, caseURL, caseStatus, 
         honorableJudge, courtHallNo, cnrNo, batchNo, dateOfFiling, practiceArea, manage, userId],
        function (err) {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Internal Server Error' });
          }
          return res.json({ message: 'Case added successfully', caseId: this.lastID });
        }
      );
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/concernedperson', authenticateJWT, async (req, res) => {
  const { caseId, client, team, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId, type, lawyerType } = req.body;

  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  const updateQuery = `
    UPDATE CasesForm SET
    client = ?, team = ?, clientDesignation = ?, opponentPartyName = ?, lawyerName = ?, 
    mobileNo = ?, emailId = ?, type = ?, lawyerType = ?
    WHERE id = ? AND user_id = ?
  `;

  const userId = req.user.id;

  db.run(
    updateQuery,
    [client, team, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId, type, lawyerType, caseId, userId],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Case not found' });
      }
      return res.json({ message: 'Case updated successfully' });
    }
  );
});

app.get('/caseformdata', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT id,title,caseCode,client,honorableJudge, opponentPartyName FROM CasesForm WHERE user_id = ?', [userId], (err, forms) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(forms);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/clientform', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT firstName FROM ClientForm WHERE user_id = ?', [userId], (err, firstName) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(firstName);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/dashboard/company', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT companyName FROM Companies WHERE user_id = ?', [userId], (err, companyName) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(companyName);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/teammemberform', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT fullName FROM TeamMembers WHERE user_id = ?', [userId], (err, fullName) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(fullName);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/companies', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT companyName FROM Companies WHERE user_id = ?', [userId], (err, companyName) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(companyName);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.delete('/dashboard/caseformdata/:caseId', authenticateJWT, async (req, res) => {
  try {
    const { caseId } = req.params;
    const userId = req.user.id;

    // Check if the case with the given ID belongs to the authenticated user
    const caseExists = await db.get(
      'SELECT id FROM CasesForm WHERE id = ? AND user_id = ?',
      [caseId, userId]
    );

    if (!caseExists) {
      return res.status(404).json({ error: 'Case not found' });
    }

    // Delete the case with the given ID
    await db.run('DELETE FROM CasesForm WHERE id = ?', [caseId]);

    return res.json({ message: 'Case deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/dashboard/caseformdata/download-pdf/:caseId', authenticateJWT, async (req, res) => {
  try {
    const { caseId } = req.params;
    const userId = req.user.id;

    // Check if the case with the given ID belongs to the authenticated user
    const caseData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM CasesForm WHERE id = ? AND user_id = ?',
        [caseId, userId],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });

    console.log('Fetched Case Data:', caseData);

    if (!caseData) {
      return res.status(404).json({ error: 'Case not found' });
    }

    // Define an HTML template for your PDF content (you can use a template engine like EJS)
    const template = `
      <html>
        <head>
          <title>Case Data</title>
        </head>
        <body>
          <h1>Case Data</h1>
          <p>Title: <%= title %></p>
          <p>Case Type: <%= caseType %></p>
          <p>Court Type: <%= courtType %></p>
          <p>Court Name: <%= courtName %></p>
          <p>Caveat No: <%= caveatNo %></p>
          <p>Case Code: <%= caseCode %></p>
          <p>Case URL: <%= caseURL %></p>
          <p>Case Status: <%= caseStatus %></p>
          <p>Honorable Judge: <%= honorableJudge %></p>
          <p>Court Hall No: <%= courtHallNo %></p>
          <p>CNR No: <%= cnrNo %></p>
          <p>Batch No: <%= batchNo %></p>
          <p>Date of Filing: <%= dateOfFiling %></p>
          <p>Practice Area: <%= practiceArea %></p>
          <p>Manage: <%= manage %></p>
          <p>Client: <%= client %></p>
          <p>Team: <%= team %></p>
          <p>Client Designation: <%= clientDesignation %></p>
          <p>Opponent Party Name: <%= opponentPartyName %></p>
          <p>Lawyer Name: <%= lawyerName %></p>
          <p>Mobile No: <%= mobileNo %></p>
          <p>Email Id: <%= emailId %></p>
        </body>
      </html>
    `;

    // Compile the template with data
    const htmlContent = ejs.render(template, caseData);

    // Create a PDF from the HTML content
    pdf.create(htmlContent).toStream((err, stream) => {
      if (err) {
        console.error(err);
        
        return res.status(500).json({ error: 'Error generating PDF' });
      }

      // Set the response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=Case_${caseData.id}.pdf`);

      // Pipe the PDF stream to the response
      stream.pipe(res);

      // Close the database connection after sending the response
      
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});



// GET endpoint to show a client in edit client form
app.get('/dashboard/clientform/edit', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT id, firstName, lastName, email, mobileNo, alternateMobileNo, organizationName, organizationType, organizationWebsite, caseTitle, type, homeAddress, officeAddress, assignAlerts, assignAppointments FROM ClientForm WHERE user_id = ?',
    [userId],
    (err, clientForms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(clientForms);
    }
  );
});
// Update endpoint to update a client in edit client form
app.put('/clients/forms/:clientId', authenticateJWT, (req, res) => {
  const clientId = req.params.clientId;
  const userId = req.user.id;
  const {
    firstName, lastName, email, mobileNo, alternateMobileNo, organizationName,
    organizationType, organizationWebsite, caseTitle, type, homeAddress, officeAddress, assignAlerts, assignAppointments
  } = req.body;

  // Check if a different record with the same email, mobileNo, and caseTitle exists
  db.get(
    'SELECT * FROM ClientForm WHERE email = ? AND mobileNo = ? AND caseTitle = ? AND id != ?',
    [email, mobileNo, caseTitle, clientId],
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (row) {
        return res.status(400).json({ error: 'Combination of Case Title, Email, and Mobile No must be unique' });
      }

      // Proceed to update the record
      db.run(
        'UPDATE ClientForm SET firstName = ?, lastName = ?, email = ?, mobileNo = ?, alternateMobileNo = ?, organizationName = ?, organizationType = ?, organizationWebsite = ?, caseTitle = ?, type = ?, homeAddress = ?, officeAddress = ?, assignAlerts = ?, assignAppointments = ? WHERE id = ? AND user_id = ?',
        [firstName, lastName, email, mobileNo, alternateMobileNo, organizationName, organizationType, organizationWebsite, caseTitle, type, homeAddress, officeAddress, assignAlerts, assignAppointments, clientId, userId],
        (updateErr) => {
          if (updateErr) {
            return res.status(500).json({ error: updateErr.message });
          }

          res.json({ message: 'Client form updated successfully' });
        }
      );
    }
  );
});


// POST endpoint to add a new client form
app.post('/dashboard/clientform', authenticateJWT, async (req, res) => {
  try {
    const { firstName, lastName, email, mobileNo, alternateMobileNo, organizationName, organizationType, organizationWebsite, caseTitle, type, homeAddress, officeAddress, assignAlerts, assignAppointments } = req.body;

    if (!firstName || !email) {
      return res.status(400).json({ error: 'First Name and Email are required fields' });
    }

    const userId = req.user.id;

    // Check for existing record with the same caseTitle, email, and mobileNo
    const uniqueCheckQuery = `SELECT * FROM ClientForm WHERE caseTitle = ? AND email = ? AND mobileNo = ?`;
    db.get(uniqueCheckQuery, [caseTitle, email, mobileNo], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (row) {
        return res.status(400).json({ error: 'Combination of Case Title, Email, and Mobile No must be unique' });
      }

      // Proceed to insert the new record
      const query = `INSERT INTO ClientForm (firstName, lastName, email, mobileNo, alternateMobileNo, organizationName, organizationType, organizationWebsite, caseTitle, type, homeAddress, officeAddress, assignAlerts, assignAppointments, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

      db.run(query, [firstName, lastName, email, mobileNo, alternateMobileNo, organizationName, organizationType, organizationWebsite, caseTitle, type, homeAddress, officeAddress, assignAlerts, assignAppointments, userId], function (err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        return res.json({ message: 'ClientForm submitted successfully' });
      });
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/clientformdata', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT id,firstName,email,mobileNo,assignAlerts,assignAppointments FROM ClientForm WHERE user_id = ?', [userId], (err, forms) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(forms);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.delete('/clientformdata/:clientId', authenticateJWT, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Check if the client with the given ID belongs to the authenticated user
    const clientExists = await db.get(
      'SELECT id FROM ClientForm WHERE id = ? AND user_id = ?',
      [clientId, req.user.id]
    );

    if (!clientExists) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Delete the client with the given ID
    await db.run('DELETE FROM ClientForm WHERE id = ?', [clientId]);

    return res.json({ message: 'Client deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.post('/reviewdocform', authenticateJWT, async (req, res) => {
  try {
    const {
      reviewMethod, contactMethod, file, text, email, mobileNo, paymentId
    } = req.body;
    const userId = req.user.id;

    if (!reviewMethod || !contactMethod) {
      return res.status(400).json({ error: 'Required fields are missing' });
    }

    db.run(`
      INSERT INTO ReviewDocForm (
        reviewMethod, contactMethod, file, text, email, mobileNo, paymentId, user_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [reviewMethod, contactMethod, file, text, email, mobileNo, paymentId, userId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json({ message: 'Review document form submitted successfully' });
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Download client PDF by ID
app.get('/clientformdata/download-pdf/:clientId', authenticateJWT, async (req, res) => {
  try {
    const { clientId } = req.params;

    // Check if the client with the given ID belongs to the authenticated user
    const clientData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM ClientForm WHERE id = ? AND user_id = ?',
        [clientId, req.user.id],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });

    if (!clientData) {
      return res.status(404).json({ error: 'Client not found' });
    }

    // Define an HTML template for your PDF content (you can use a template engine like EJS)
    const template = `
    <html>
    <head>
      <title>Client Data</title>
    </head>
    <body>
      <h1>Client Data</h1>
      <p>First Name: <%= firstName %></p>
      <p>Last Name: <%= lastName %></p>
      <p>Email: <%= email %></p>
      <p>Mobile No: <%= mobileNo %></p>
      <p>Alternate Mobile No: <%= alternateMobileNo %></p>
      <p>Organization Name: <%= organizationName %></p>
      <p>Organization Type: <%= organizationType %></p>
      <p>Organization Website: <%= organizationWebsite %></p>
      <p>Case: <%= caseTitle %></p>
      <p>Type: <%= type %></p>
      <p>Home Address: <%= homeAddress %></p>
      <p>Office Address: <%= officeAddress %></p>
      <p>Assign Alerts: <%= assignAlerts %></p>
      <p>Assign Appointments: <%= assignAppointments %></p>
      
    </body>
  </html>
    `;

    // Compile the template with data
    const htmlContent = ejs.render(template, clientData);

    // Create a PDF from the HTML content
    pdf.create(htmlContent).toStream((err, stream) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error generating PDF' });
      }

      // Set the response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=Client_${clientData.id}.pdf`);

      // Pipe the PDF stream to the response
      stream.pipe(res);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});




app.get('/dashboard/alertsform', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT title FROM AlertsForm WHERE user_id = ?', [userId], (err, title) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(title);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


// POST endpoint to add a new CNR form
app.post('/cnr', authenticateJWT, async (req, res) => {
  try {
    const { hearingCourt, caseType, caseNo, caseYear } = req.body;
    const userId = req.user.id;

    if (!hearingCourt || !caseType || !caseNo || !caseYear) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    const query = `
      INSERT INTO CnrForm (hearingCourt, caseType, caseNo, caseYear, user_id)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.run(
      query,
      [hearingCourt, caseType, caseNo, caseYear, userId],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        return res.json({ message: 'CNR form submitted successfully' });
      }
    );
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


//Group form endpoints
app.post('/dashboard/groupform', authenticateJWT, async (req, res) => {
  try {
    const { groupName, company, priority } = req.body;
    const userId = req.user.id;

    if (!groupName || !priority) {
      return res.status(400).json({ error: 'Group name and priority are required' });
    }

    db.run('INSERT INTO GroupForm (groupName, company, priority, user_id) VALUES (?, ?, ?, ?)', [groupName, company, priority, userId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json({ message: 'Group form submitted successfully' });
    });
  } catch (error) {
    console.log(error);
  }
});

//endpoint for render invoice data on edit form of invoice
//endpoint for render invoice data on edit form of invoice
app.get('/invoiceform/edit', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT id, invoiceNumber, client, caseType, date, amount, taxType, taxPercentage, fullAddress, hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType, expensesTaxPercentage, expensesCumulativeAmount,totalAmount,CumulativeAmount, addDoc FROM InvoicesForm WHERE user_id = ?',
    [userId],
    (err, invoicesForms) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json(invoicesForms);
    }
  );
});
//endpoint for updating the renderinformation on edit form of invoice
app.put('/invoiceform/edit/update/:invoiceId', authenticateJWT, (req, res) => {
  const invoiceId = req.params.invoiceId;
  const userId = req.user.id;
  
    
  const {
    invoiceNumber,CumulativeAmount, client, caseType, date, amount, taxType, taxPercentage, fullAddress,
    hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType, expensesTaxPercentage, expensesCumulativeAmount,totalAmount, addDoc
  } = req.body;

  db.run(
    'UPDATE InvoicesForm SET invoiceNumber = ?,CumulativeAmount = ?, client = ?, caseType = ?, date = ?, amount = ?, taxType = ?, taxPercentage = ?, fullAddress = ?, hearingDate = ?, title = ?, dateFrom = ?, dateTo = ?, expensesAmount = ?, expensesTaxType = ?, expensesTaxPercentage = ?, expensesCumulativeAmount = ?,totalAmount = ?, addDoc = ? WHERE id = ? AND user_id = ?',
    [invoiceNumber,CumulativeAmount, client, caseType, date, amount, taxType, taxPercentage, fullAddress, hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType, expensesTaxPercentage, expensesCumulativeAmount,totalAmount,  addDoc, invoiceId, userId],
    (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({ message: 'Invoice form updated successfully' });
    }
  );
});

app.post('/uploaddoc', upload.single('addDoc'), (req, res) => {
  if (req.file) {
    // res.json({ filePath: req.file.path });
    const filename = req.file.filename; // Adjust this line to get only the filename
    res.json({ filePath: filename });
  } else {
    res.status(400).json({ error: 'No file uploaded.' });
  }
});

//Invoice Form endpoints
app.post('/invoiceform', authenticateJWT, async (req, res) => {
  try {
    const {
      invoiceNumber, CumulativeAmount, client, caseType, date, amount, taxType, taxPercentage,
      fullAddress, hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType,
      expensesTaxPercentage, expensesCumulativeAmount, totalAmount, addDoc
    } = req.body;
    const userId = req.user.id; // Extracted from JWT token, assumed available

    if (!invoiceNumber || !title) {
      return res.status(400).json({ error: 'Required fields are missing' });
    }

    // Database insertion
    const insertQuery = `
      INSERT INTO InvoicesForm (
        invoiceNumber, CumulativeAmount, client, caseType, date, amount, taxType, taxPercentage,
        fullAddress, hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType,
        expensesTaxPercentage, expensesCumulativeAmount, totalAmount, addDoc, user_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.run(insertQuery, [
      invoiceNumber, CumulativeAmount, client, caseType, date, amount, taxType, taxPercentage,
      fullAddress, hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType,
      expensesTaxPercentage, expensesCumulativeAmount, totalAmount, addDoc, userId
    ], function(err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Error inserting data into database' });
      }
      return res.json({ message: 'Invoice form submitted successfully', invoiceId: this.lastID });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/invoiceformdata', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  
  db.all('SELECT id,title, invoiceNumber , date, client,totalAmount FROM InvoicesForm WHERE user_id = ?', [userId], (err, forms) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json(forms);
  });
});
app.delete('/invoiceformdata/:invoiceId', authenticateJWT, async (req, res) => {
  try {
    const { invoiceId } = req.params;

    // Check if the invoice with the given ID belongs to the authenticated user
    const invoiceExists = await db.get(
      'SELECT id FROM InvoicesForm WHERE id = ? AND user_id = ?',
      [invoiceId, req.user.id]
    );

    if (!invoiceExists) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    // Delete the invoice with the given ID
    await db.run('DELETE FROM InvoicesForm WHERE id = ?', [invoiceId]);

    return res.json({ message: 'Invoice deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Download invoice PDF by ID
app.get('/invoiceformdata/download-pdf/:invoiceId', authenticateJWT, async (req, res) => {
  try {
    const { invoiceId } = req.params;

    // Check if the invoice with the given ID belongs to the authenticated user
    const invoiceData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM InvoicesForm WHERE id = ? AND user_id = ?',
        [invoiceId, req.user.id],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row);
          }
        }
      );
    });

    if (!invoiceData) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    // Define an HTML template for your PDF content (you can use a template engine like EJS)
    const template = `
    <html>
<head>
  <title>Invoice Data</title>
</head>
<body>
  <h1>Invoice Data</h1>
  <p>Title: <%= title %></p>
  <p>Invoice Number: <%= invoiceNumber %></p>
  <p>Date: <%= date %></p>
  <p>Client: <%= client %></p>
  <p>Case Type: <%= caseType %></p>
  <p>Amount: <%= amount %></p>
  <p>Tax Type: <%= taxType %></p>
  <p>Tax Percentage: <%= taxPercentage %></p>
  <p>Cumulative Amount: <%= CumulativeAmount %></p>
  <p>Full Address: <%= fullAddress %></p>
  <p>Date From: <%= dateFrom %></p>
  <p>Date To: <%= dateTo %></p>
  <p>Expenses Amount: <%= expensesAmount %></p>
  <p>Expenses Tax Type: <%= expensesTaxType %></p>
  <p>Expenses Tax Percentage: <%= expensesTaxPercentage %></p>
  <p>Expenses Cumulative Amount: <%= expensesCumulativeAmount %></p>
  <p>Total Amount with all Expenses : <%= totalAmount %></p>
  <!-- Add more fields as needed -->
</body>
</html>
    `;

    // Compile the template with data
    const htmlContent = ejs.render(template, invoiceData);

    // Create a PDF from the HTML content
    pdf.create(htmlContent).toStream((err, stream) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error generating PDF' });
      }

      // Set the response headers for PDF download
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename=Invoice_${invoiceData.id}.pdf`);

      // Pipe the PDF stream to the response
      stream.pipe(res);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});





app.get('/clientform', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT firstName FROM ClientForm WHERE user_id = ?', [userId], (err, firstName) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(firstName);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/caseform', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT id, title, type_name FROM UpdateCases WHERE user_id = ?', [userId], (err, cases) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json(cases);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/dashboard/people/appointmentsdates', authenticateJWT, (req, res) => {
  try {
    const userId = req.user.id;
    db.all('SELECT id, title, appointmentDate FROM Appointments WHERE user_id = ?', [userId], (err, appointments) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      
      // Format the data to include title and appointmentDate as "title(appointmentDate)"
      const formattedAppointments = appointments.map(appointment => ({
        id: appointment.id,
        title: `${appointment.title} (${appointment.appointmentDate})`,
      }));
      
      return res.json(formattedAppointments);
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


//party Name form endpoints
app.post('/partyname', authenticateJWT, async (req, res) => {
  try {
    const { hearingCourt, partyName, caseYear } = req.body;
    const userId = req.user.id;

    if (!hearingCourt || !partyName || !caseYear) {
      return res.status(400).json({ error: 'Hearing court, party name, and case year are required' });
    }

    db.run('INSERT INTO PartyNameForm (hearingCourt, partyName, caseYear, user_id) VALUES (?, ?, ?, ?)', [hearingCourt, partyName, caseYear, userId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json({ message: 'Party name form submitted successfully' });
    });
  } catch (error) {
    console.log(error);
  }
});





//review doc form endpoints
app.post('/reviewdoc', authenticateJWT, async (req, res) => {
  try {
    const { reviewMethod, contactMethod, file, text, mobileNo } = req.body;
    const userId = req.user.id;

    if (!reviewMethod || !contactMethod) {
      return res.status(400).json({ error: 'Review method and contact method are required' });
    }

    db.run('INSERT INTO ReviewDocForm (reviewMethod, contactMethod, file, text, mobileNo, user_id) VALUES (?, ?, ?, ?, ?, ?)', [reviewMethod, contactMethod, file, text, mobileNo, userId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      return res.json({ message: 'Review document form submitted successfully' });
    });
  } catch (error) {
    console.log(error);
  }
});
// NOTIFICATIONS FOR ALERTS
app.get('/dashboard/user/notifications', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  const currentDate = new Date();

  console.log('userId:', userId);
  console.log('currentDate:', currentDate.toISOString());

  db.all(
    `
    SELECT id, message, expirationDate FROM Notification WHERE user_id = ? AND date(expirationDate) >= date('now') AND type = 'general'
    `,
    [userId],
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      try {
        const notifications = rows.map(row => {
          const expirationDate = new Date(row.expirationDate);
          const daysDifference = Math.floor(
            (expirationDate - currentDate) / (24 * 60 * 60 * 1000) 
          );

          let timeLeftMessage;
          if (daysDifference <= 0) {
            timeLeftMessage = "Less than 24hrs left";
          } else {
            timeLeftMessage = `${daysDifference} days left`;
          }

          return {
            id: row.id,
            message: `${timeLeftMessage}: ${row.message}`,
          };
        });

        console.log('Retrieved rows:', rows);

        return res.json(notifications);
      } catch (error) {
        console.error('Processing error:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
    }
  );
});
app.put('/dashboard/user/notifications/viewed', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.run(`UPDATE Notification SET isViewed = 1 WHERE user_id = ?`, [userId], (err) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ message: 'Notifications marked as viewed' });
  });
});

app.get('/dashboard/user/notifications/count', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.get(`SELECT COUNT(*) AS count FROM Notification WHERE user_id = ? AND isViewed = 0`, [userId], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ count: row.count });
  });
});

app.delete('/dashboard/user/notifications/:notificationId', authenticateJWT, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user.id;

    // Check if the notification with the given ID belongs to the authenticated user
    const notificationExists = await new Promise((resolve, reject) => {
      db.get(`SELECT id FROM Notification WHERE id = ? AND user_id = ?`, [notificationId, userId], (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      });
    });

    if (!notificationExists) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    // Delete the notification with the given ID
    await new Promise((resolve, reject) => {
      db.run(`DELETE FROM Notification WHERE id = ?`, [notificationId], (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });

    return res.json({ message: 'Notification deleted successfully' });
  } catch (error) {
    console.error('Database error:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

const getAsync = (sql, params) => new Promise((resolve, reject) => {
  db.get(sql, params, (err, row) => {
    if (err) reject(err);
    else resolve(row);
  });
});

// Promisified run method
const runAsync = (sql, params) => new Promise((resolve, reject) => {
  db.run(sql, params, function(err) {
    if (err) reject(err);
    else resolve(this);
  });
});

// notifications for proxy
app.post('/proxy', authenticateJWT, async (req, res) => {
  const userId = req.user.id; // Extracting user ID from JWT authentication

  // Extracting data from request body
  const {
    lawyerType,
    experience,
    age,
    streetAddress,
    city,
    zipStateProvince,
    zipPostalCode,
    date,
    caseDescription,
    causeTitle,
    honorableJudge,
    courtNumber,
    type,
    timeOfHearing,
    dateOfHearing,
    comments
  } = req.body;

  // Calculating expirationDate based on dateOfHearing
  const expirationDate = new Date(dateOfHearing).toISOString();

  // SQL query to insert proxy form data
  const insertProxySQL = `
    INSERT INTO ProxyForm (
      lawyerType,
      experience,
      age,
      streetAddress,
      city,
      zipStateProvince,
      zipPostalCode,
      date,
      caseDescription,
      causeTitle,
      honorableJudge,
      courtNumber,
      type,
      timeOfHearing,
      dateOfHearing,
      comments,
      user_id,
      expirationDate
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  try {
    // Inserting proxy form data into the database
    const result = await runAsync(insertProxySQL, [
      lawyerType,
      experience,
      age,
      streetAddress,
      city,
      zipStateProvince,
      zipPostalCode,
      date,
      caseDescription,
      causeTitle,
      honorableJudge,
      courtNumber,
      type,
      timeOfHearing,
      dateOfHearing,
      comments,
      userId,
      expirationDate
    ]);

    const proxyId = result.lastID; // Retrieve the last inserted ID for the proxy

    console.log('Proxy form data inserted successfully. Proxy ID:', proxyId);

    // Fetch all user IDs except the current user's
    const allUserIds = await new Promise((resolve, reject) => {
      db.all(`SELECT id FROM users WHERE id != ?`, [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows.map(row => row.id));
      });
    });

    // Constructing the notification message
    const createdByUser = await new Promise((resolve, reject) => {
      db.get('SELECT name FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row.name); // Assuming the user has a 'name' column
      });
    });
    const notificationMessage = `A new proxy has been generated by ${createdByUser}. Need a ${lawyerType} lawyer with ${experience} years of experience and around ${age} years old. The hearing date is on ${dateOfHearing} in ${city}, ${zipStateProvince}.`;

    // Inserting notification for each user except the creator
    for (const id of allUserIds) {
      await runAsync('INSERT INTO Notification (user_id, message, expirationDate, type, proxy_id) VALUES (?, ?, ?, ?, ?)', [
        id,
        notificationMessage,
        expirationDate,
        'proxy',
        proxyId
      ]);
    }

    console.log('Notifications inserted successfully for all users except the creator');
    res.status(201).json({ message: 'Proxy created successfully', notification: notificationMessage });
  } catch (error) {
    console.error('Error in /proxy endpoint:', error);
    res.status(500).json({ error: 'Internal Server Error', details: error.message });
  }
});



app.get('/dashboard/user/proxy-notifications', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  // Adjusted query to exclude finalized proxies
  const query = `
    SELECT n.id, n.message, n.expirationDate, n.proxy_id
    FROM Notification n
    JOIN ProxyForm pf ON n.proxy_id = pf.id
    WHERE n.user_id = ? AND date(n.expirationDate) >= date('now') AND n.type = 'proxy' AND pf.status != 'finalized'
  `;

  db.all(query, [userId], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    return res.json(rows.map(row => ({
      ...row,
      proxyId: row.proxy_id
    })));
  });
});






app.post('/dashboard/user/accept-proxy/:proxyId', authenticateJWT, async (req, res) => {
  console.log(`Accepting proxy with ID: ${req.params.proxyId}`);
  const userId = req.user.id; // From JWT authentication
  const proxyId = req.params.proxyId;

  try {
    // Check if the proxy exists and is pending
    const proxy = await getAsync('SELECT * FROM ProxyForm WHERE id = ?', [proxyId]);
    if (!proxy) {
      return res.status(404).json({ error: 'Proxy not found' });
    }

    // Insert acceptance record
    const currentDate = new Date().toISOString();
    await runAsync('INSERT INTO ProxyAcceptance (proxy_id, user_id, acceptanceDate) VALUES (?, ?, ?)', [proxyId, userId, currentDate]);
    await runAsync('DELETE FROM Notification WHERE proxy_id = ? AND user_id = ?', [proxyId, userId]);
    

    // Fetch user details
    const user = await getAsync('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Construct the notification message
    const notificationMessage = `${user.name} has accepted your proxy for hearing date ${proxy.dateOfHearing}.He is a ${user.lawyerType} , ${user.age} years old and having ${user.experience} years of experience. You can contact me through email-${user.username} or by mobile-${user.mobile} `;

    // Insert the notification for the proxy creator
    await runAsync('INSERT INTO Notification (user_id, message, expirationDate, type, proxy_id, acceptorId) VALUES (?, ?, ?, ?, ?, ?)', [proxy.user_id, notificationMessage, proxy.expirationDate, 'proxy-accepted', proxy.id, userId]);

    res.status(201).json({ message: 'Proxy accepted successfully', notificationMessage });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Internal Server Error', details: error.message });
  }
});


app.get('/dashboard/user/proxy-notifications-accepted', authenticateJWT, (req, res) => {
  const userId = req.user.id; // Extracting user ID from JWT authentication

  db.all(`
    SELECT 
      n.id AS notificationId, 
      n.message, 
      n.expirationDate, 
      n.proxy_id AS proxyId, 
      n.acceptorId
    FROM Notification n
    JOIN ProxyForm pf ON n.proxy_id = pf.id AND pf.user_id = ?
    WHERE 
      n.expirationDate >= date('now') 
      AND n.type = 'proxy-accepted'
    ORDER BY n.proxy_id, n.id
  `, [userId], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    res.json(rows);
  });
});






app.post('/dashboard/user/choose-acceptor/:proxyId/:acceptorId', authenticateJWT, async (req, res) => {
  console.log("params", req.params)
  const userId = req.user.id; // ID of the user making the request, should be the creator of the proxy
  const { proxyId, acceptorId } = req.params;
  const { paymentId } = req.body; 

  try {
    // Use the promisified getAsync to verify the requester is the creator of the proxy
    const proxy = await getAsync('SELECT * FROM ProxyForm WHERE id = ? AND user_id = ?', [proxyId, userId]);
    if (!proxy) {
      return res.status(404).json({ error: 'Proxy not found or you do not have permission to finalize this proxy.' });
    }



    await runAsync('UPDATE ProxyForm SET paymentId = ?, payment_status = ? WHERE id = ?', [paymentId, 'successful', proxyId]);

    // The rest of your logic to handle acceptor choice...
    // Ensure to check if a valid acceptorId is provided and matches the expected criteria

    

    const acceptance = await getAsync('SELECT * FROM ProxyAcceptance WHERE proxy_id = ? AND user_id = ?', [proxyId, acceptorId]);
    if (!acceptance) {
      return res.status(400).json({ error: 'The chosen acceptor does not match any proxy acceptance record.' });
    }


    // Use the promisified runAsync to update ProxyForm status to "finalized"
    const currentDate = new Date().toISOString().split('T')[0];

    // Use the promisified runAsync to update ProxyForm status to "finalized" and set the acceptanceDate
    await runAsync('UPDATE ProxyForm SET status = "finalized", acceptanceDate = ?, accepted_by_user_id = ? WHERE id = ?', [currentDate, acceptorId, proxyId]);
    await runAsync('DELETE FROM Notification WHERE proxy_id = ? AND user_id = ?', [proxyId, userId]);
    // Fetch the creator's details to include in the notification
    const creator = await getAsync('SELECT * FROM users WHERE id = ?', [userId]);
    if (!creator) {
      return res.status(404).json({ error: 'Creator user not found.' });
    }

    // Correcting the logic: Construct and send a notification message to the acceptor, indicating the creator has finalized their acceptance
    const notificationMessageForAcceptor = `Your request to accept the proxy for hearing date ${proxy.dateOfHearing} has been successfully accepted by ${creator.name}. You may contact them by email ${creator.username} or mobile ${creator.mobile}.`;

    // Ensure the notification is sent to the acceptor
    await runAsync('INSERT INTO Notification (user_id, message, expirationDate, proxy_id) VALUES (?, ?, ?, ?)', [acceptorId, notificationMessageForAcceptor, proxy.expirationDate , proxy.id]);

    res.json({ message: 'Acceptor chosen successfully, notifications sent.' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// show proxy
// Endpoint for retrieving proxy activity for the logged-in user
app.get('/dashboard/user/proxy-activity', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  const currentDate = new Date().toISOString();

  db.all(
    `SELECT 
        pa.id, 
        pa.acceptanceDate, 
        pa.hearingDate, 
        pa.zipStateProvince, 
        pa.type, 
        creator.name AS creatorFullName,  -- Adjusted to fetch creator's full name
        acceptor.name AS acceptorFullName -- Adjusted for clarity and consistency
     FROM ProxyActivity pa
     INNER JOIN users acceptor ON pa.acceptor_user_id = acceptor.id -- Join for acceptor
     INNER JOIN users creator ON pa.creator_user_id = creator.id -- Join for creator
     INNER JOIN ProxyForm p ON pa.proxy_id = p.id
     WHERE pa.creator_user_id = ? AND p.expirationDate > ?`,
    [userId, currentDate],
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }

      try {
        const proxyActivity = rows.map((row) => {
          return {
            id: row.id,
            acceptanceDate: row.acceptanceDate,
            hearingDate: row.hearingDate,
            zipStateProvince: row.zipStateProvince,
            type: row.type,
            creatorFullName: row.creatorFullName, // Reflects the creator's full name
            acceptorFullName: row.acceptorFullName, // Reflects the acceptor's full name
          };
        });

        return res.json(proxyActivity);
      } catch (error) {
        console.error('Processing error:', error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
    }
  );
});



// Endpoint for deleting proxy activity for the logged-in user
app.delete('/dashboard/user/proxy-activity/:activityId', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  const activityId = req.params.activityId;
  // Check if the activity with the given ID exists and belongs to the authenticated user
  db.get(
    'SELECT id FROM ProxyActivity WHERE id = ? AND creator_user_id = ?',
    [activityId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Proxy Activity not found' });
      }
      // Delete the proxy activity with the specified ID
      db.run('DELETE FROM ProxyActivity WHERE id = ?', [activityId], (deleteErr) => {
        if (deleteErr) {
          console.error('Database error:', deleteErr);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        return res.json({ message: 'Proxy Activity deleted successfully' });
      });
    }
  );
});


// count apis shown on each card in dashboard
app.get('/casecount', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT COUNT(*) as count FROM CasesForm WHERE user_id = ?', [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json({ count: result.count });
  });
});


app.get('/clientcount', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT COUNT(*) as count FROM ClientForm WHERE user_id = ?', [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json({ count: result.count });
  });
});


app.get('/teammembercount', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT COUNT(*) as count FROM TeamMembers WHERE user_id = ?', [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json({ count: result.count });
  });
});

app.get('/alertcount', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT COUNT(*) as count FROM AlertsForm WHERE user_id = ?', [userId], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    return res.json({ count: result.count });
  });
});

app.get('/invoicebillcount', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT COUNT(*) as invoiceCount FROM InvoicesForm WHERE user_id = ?', [userId], (err, invoiceResult) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    db.get('SELECT COUNT(*) as billCount FROM BillForm WHERE user_id = ?', [userId], (err, billResult) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      const totalCount = invoiceResult.invoiceCount + billResult.billCount;
      return res.json({ invoiceCount: invoiceResult.invoiceCount, billCount: billResult.billCount, totalCount });
    });
  });
});


app.get('/profile', authenticateJWT, (req, res) => {
  const userId = req.user.id;
  console.log("yoyohoney",userId)
  db.get('SELECT id,username, name, mobile, lawyerType, experience, age FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    // Check if the user exists
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json(user);
  });
});


app.patch('/profile/edit/update', authenticateJWT, (req, res) => {
  console.log(req.body); 
  const userId = req.user.id;
  const { name, mobile, lawyerType, experience, age } = req.body;
  // Ensure that at least one field is provided for update
  if (!name && !mobile && !lawyerType && !experience && !age) {
    return res.status(400).json({ error: 'At least one field must be provided for update' });
  }
  // Build the SET clause for the update query dynamically
  const updateFields = [];
  const updateValues = [];
  if (name) {
    updateFields.push('name = ?');
    updateValues.push(name);
  }
  if (mobile) {
    updateFields.push('mobile = ?');
    updateValues.push(mobile);
  }
  if (lawyerType) {
    updateFields.push('lawyerType = ?');
    updateValues.push(lawyerType);
  }
  if (experience) {
    updateFields.push('experience = ?');
    updateValues.push(experience);
  }
  if (age) {
    updateFields.push('age = ?');
    updateValues.push(age);
  }
  const updateQuery = `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`;
  const updateParams = [...updateValues, userId];

  db.run(updateQuery, updateParams, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found or no changes made' });
    }
    return res.json({ message: 'Profile updated successfully' });
  });
});


// Error handler middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal Server Error', details: err.message });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
