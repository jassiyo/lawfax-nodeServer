const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const secretKey = 'your_secret_key';
const ejs = require('ejs');
const pdf = require('html-pdf');
const puppeteer = require('puppeteer');
const fetch = require('node-fetch');
const FormData = require('form-data');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const path = require('path');
// const PDFParse = require('pdf-parse');
const PDFDocument = require('pdfkit');
app.use(cors()); // Enable CORS for all routes
app.use(express.json()); // Parse JSON bodies
const fs = require('fs');
app.use(express.json());
const Razorpay = require('razorpay');
const dotenv = require('dotenv');
const axios = require('axios');
const http = require('http');
const socketIo = require('socket.io');
dotenv.config();

// const { Storage } = require('@google-cloud/storage');
const port = process.env.PORT || 8052;
const razorpayAuth = {
  username: process.env.RAZORPAY_KEY_ID,
  password: process.env.RAZORPAY_KEY_SECRET,
};

const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});


const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, './Db-data/uploads'),
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
  secure: false,
  // port: process.env.PORT || 465,
  // secure: true,
  auth: {
    user: 'lawfax23@gmail.com',
    pass: 'ahgo nnym gsvu ipxq'
    // user: 'nupurgarg8792@gmail.com',
    // pass: 'zaal owwv ivsn ctht'
  }
});

//verification of user email
function sendVerificationEmail(email, token) {
  const verificationLink = `http://localhost:3000/verifyemail/${token}`;
  const mailOptions = {
    from: 'lawfax23@gmail.com',
    to: email,
    subject: 'Verify Your Email',
    html: `<p>Click <a href="${verificationLink}">here</a> to verify your email.</p>`
  };
  transporter.sendMail(mailOptions, function (error, info) {
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
    from: 'lawfax23@gmail.com',
    from: 'lawfax23@gmail.com',
    to: email,
    subject: 'Reset Your Password',
    html: `<p>Click <a href="${verificationLink}">here</a> to reset your password</p>`
  };
  transporter.sendMail(mailOptions, function (error, info) {
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
    avatar_url TEXT,
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
const checkAccess = (req, res, next) => {
  const userId = req.user.id; // Assuming you're extracting this from JWT token

  db.get('SELECT trial_start_date, subscription_end_date FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Normalize today's date to start of day for comparison
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let isAccessAllowed = false;

    let trialEndDate = user.trial_start_date ? new Date(user.trial_start_date) : null;
    if (trialEndDate) {
      trialEndDate.setDate(trialEndDate.getDate() + 15);
      trialEndDate.setHours(0, 0, 0, 0); // Normalize trial end date
      if (today <= trialEndDate) {
        isAccessAllowed = true;
      }
    }

    let subscriptionEndDate = user.subscription_end_date ? new Date(user.subscription_end_date) : null;
    if (subscriptionEndDate) {
      subscriptionEndDate.setHours(0, 0, 0, 0); // Normalize subscription end date
      if (today <= subscriptionEndDate) {
        isAccessAllowed = true;
      }
    }

    // Proceed to next middleware if access is allowed
    if (isAccessAllowed) {
      next();
    } else {
      return res.status(403).json({ message: "Access denied. Please subscribe to continue." });
    }
  });
};

const sendEmail = (to, subject, text, callback) => {
  const mailOptions = {
    from: 'lawfax23@gmail.com',
    to: to,
    subject: subject,
    text: text,
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
    callback(error, info);
  });
};

const checkAndSendNotifications = () => {
  const today = new Date().toISOString().split('T')[0];
  const query = `
    SELECT n.id, n.user_id, n.message, n.expirationDate, u.username as userEmail 
    FROM Notification n
    JOIN users u ON n.user_id = u.id
    WHERE n.emailed = 0 AND date(n.expirationDate) >= date('now')
    AND u.emailNoti = 1
    AND (
      (date(u.trial_start_date, '+15 days') >= date('${today}') OR
      date(u.subscription_end_date) >= date('${today}'))
    )
  `;

  db.all(query, [], (err, notifications) => {
    if (err) {
      console.error('Database error:', err);
      return;
    }

    notifications.forEach(notification => {
      const emailSubject = 'Notification from LawFax';
      const emailBody = notification.message;

      // Send an email for each notification
      sendEmail(notification.userEmail, emailSubject, emailBody, () => {
        // Update the notification as emailed
        db.run(`UPDATE Notification SET emailed = 1 WHERE id = ?`, [notification.id], (updateErr) => {
          if (updateErr) {
            console.error('Failed to update notification as emailed:', updateErr);
          }
        });
      });
    });
  });
};

// Run this function periodically
setInterval(checkAndSendNotifications, 60000);// Example: run every 60 seconds


app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  credentials: true
}));

// Authentication middleware
// function authenticateJWT(req, res, next) {
//   const token = req.header('x-auth-token');
//   if (!token) {
//     return res.status(401).json({ error: 'Access denied. No token provided.' });
//   }

//   try {
//     const decoded = jwt.verify(token, secretKey);
//     req.user = decoded;
//     next();
//   } catch (ex) {
//     res.status(400).json({ error: 'Invalid token.' });
//   }
// }
function authenticateJWT(req, res, next) {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, secretKey);
    db.get('SELECT current_session_id FROM users WHERE id = ?', [decoded.id], (err, row) => {
      if (err || !row) {
        return res.status(500).json({ error: 'Failed to validate session.' });
      }
      if (decoded.sessionId !== row.current_session_id) {
        return res.status(401).json({ error: 'Your session has expired. Please log in again.' });
      }
      req.user = decoded;
      next();
    });
  } catch (ex) {
    if (ex.name === "TokenExpiredError") {
      return res.status(401).json({ error: 'Token expired.' });
    } else {
      return res.status(400).json({ error: 'Invalid token.' });
    }
  }
}
function authenticateAdminJWT(req, res, next) {
  const token = req.header('x-auth-token'); // Or req.headers.authorization if you're using Bearer tokens
  if (!token) {
    
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  // else {
  //   return("token", token)
  // }

  try {
    const decoded = jwt.verify(token, secretKey);
    // Directly assign the decoded JWT payload to req.user without checking the current session ID
    req.admin = decoded;
    next();
  } catch (ex) {
    if (ex.name === "TokenExpiredError") {
      return res.status(401).json({ error: 'Token expired.' });
    } else {
      return res.status(400).json({ error: 'Invalid token.' });
    }
  }
}


// for load balancer
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', './index.html'));
});

//admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM admins WHERE username = ?', [username], async (err, admin) => {
    if (err) {
      return res.status(500).json({ error: 'Internal server error' });
    }
    if (!admin) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const validPassword = await bcrypt.compare(password, admin.hashed_password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, isAdmin: true },
      secretKey
     
    );
    console.log('admin token', token)

    res.json({ token });
  });
});

app.get('/admin/proxy-payments', authenticateAdminJWT, async (req, res) => {
  try {
    const query = `SELECT * FROM ProxyForm WHERE payment_status = 'successful' ORDER BY id DESC`;
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ proxies: rows });
    });
  } catch (error) {
    console.error('Error fetching proxy payments:', error);
    res.status(500).json({ error: 'Failed to fetch proxy payments' });
  }
});
app.get('/admin/updated-cases', authenticateAdminJWT, async (req, res) => {
  try {
    // You can customize the ORDER BY clause based on your requirements
    const query = `SELECT * FROM UpdateCases ORDER BY id DESC`;
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ cases: rows });
    });
  } catch (error) {
    console.error('Error fetching updated cases:', error);
    res.status(500).json({ error: 'Failed to fetch updated cases' });
  }
});


app.post('/admin/proxy-payments/:id/execute-payment', authenticateAdminJWT, async (req, res) => {
  const { id } = req.params; // Proxy ID
  const { isAdminApproved } = req.body; // This assumes the request includes an 'isAdminApproved' field.

  // First, update the admin approval status.
  const updateApprovalQuery = `UPDATE ProxyForm SET isAdminApproved = ? WHERE id = ?`;
  db.run(updateApprovalQuery, [isAdminApproved, id], function (err) {
    if (err) {
      console.error('Database error on updating admin approval:', err.message);
      return res.status(500).json({ error: 'Internal Server Error on updating admin approval' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Proxy not found or no change in admin approval status.' });
    }

    // Assuming admin approval update was successful, now proceed to check and execute payment.
    db.get(`SELECT * FROM ProxyForm WHERE id = ?`, [id], (err, proxy) => {
      if (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (!proxy) {
        return res.status(404).json({ error: 'Proxy not found' });
      }
      if (proxy.payment_executed) {
        return res.status(400).json({ error: 'Payment has already been executed for this proxy' });
      }

      // Determine target user and amount based on attendance
      let targetUserId, amount;
      if (proxy.attendance === 'A') { // Absent, refund to generator
        targetUserId = proxy.user_id;
        amount = parseFloat(proxy.age); // Assuming 'age' stores the fee paid by generator
      } else if (proxy.attendance === 'P') { // Present, pay to acceptor
        targetUserId = proxy.accepted_by_user_id;
        amount = parseFloat(proxy.age) * 0.95; // Assuming 'age' stores the fee, and payee gets 95%
      } else {
        return res.status(400).json({ error: 'Invalid attendance status' });
      }

      // Update wallet balance for target user
      db.run(`UPDATE wallets SET balance = balance + ? WHERE user_id = ?`, [amount, targetUserId], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update wallet balance' });
        }
        if (this.changes > 0) {
          // After updating wallet, mark the payment as executed
          db.run(`UPDATE ProxyForm SET payment_executed = 1 WHERE id = ?`, [id], function(err) {
            if (err) {
              return res.status(500).json({ error: 'Failed to mark payment as executed' });
            }
            res.json({ message: 'Admin approval updated and payment executed successfully.' });
          });
        } else {
          res.status(404).json({ error: 'Wallet not found for user.' });
        }
      });
    });
  });
});
// Endpoint to update attendance
app.post('/admin/proxy-payments/:id/update-attendance', authenticateAdminJWT, async (req, res) => {
  const { id } = req.params;
  const { attendance } = req.body; // New attendance status ('A' or 'P')

  const updateAttendanceQuery = `UPDATE ProxyForm SET attendance = ? WHERE id = ?`;

  db.run(updateAttendanceQuery, [attendance, id], function(err) {
    if (err) {
      console.error('Database error on updating attendance:', err.message);
      return res.status(500).json({ error: 'Internal Server Error on updating attendance' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Proxy not found or no change in attendance status.' });
    }

    res.json({ message: 'Attendance updated successfully.' });
  });
});

app.get('/admin/new-users', authenticateAdminJWT, async (req, res) => {
  try {
    // Fetch users ordered by registration date
    const query = `SELECT * FROM users ORDER BY registration_date DESC, id DESC`;
    db.all(query, [], (err, users) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      
      // Optionally, group users by registration_date here if needed

      res.json({ users: users });
    });
  } catch (error) {
    console.error('Error fetching new users:', error);
    res.status(500).json({ error: 'Failed to fetch new users' });
  }
});
async function getUsersByRegistrationDate(registrationDate) {
  return new Promise((resolve, reject) => {
    db.all("SELECT * FROM users WHERE registration_date = ?", [registrationDate], (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}
app.get('/dashboard/new-users/download-pdf/:registrationDate', authenticateAdminJWT, async (req, res) => {
  try {
    const { registrationDate } = req.params;

    // Assuming a function that retrieves users based on the registration date
    const usersData = await getUsersByRegistrationDate(registrationDate);

    if (!usersData || usersData.length === 0) {
      return res.status(404).json({ error: 'No users found for this date' });
    }

    // HTML template for PDF
    let htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Users Registered on ${registrationDate}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 20px;
            margin: 0;
            background: #ffffff;
            color: #333;
        }
        
        h1 {
          text-align: center;
            color: #333;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            text-align: left;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <h1>Users Registered on ${registrationDate}</h1>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Username</th>
                <th>Mobile</th>
            </tr>
        </thead>
        <tbody>`;

    usersData.forEach(user => {
      htmlContent += `
            <tr>
                <td>${user.id}</td>
                <td>${user.name}</td>
                <td>${user.username}</td>
                <td>${user.mobile}</td>
            </tr>`;
    });

    htmlContent += `
        </tbody>
    </table>
</body>
</html>`;

    // Launch Puppeteer and generate the PDF
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
    const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
    await browser.close();

    // Set the response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=users-${registrationDate}.pdf`);

    // Send the PDF buffer in the response
    res.send(pdfBuffer);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.post('/admin/update-status/:registrationDate', authenticateAdminJWT, async (req, res) => {
  const { registrationDate } = req.params;
  const { newStatus } = req.body; // Assuming newStatus is a boolean indicating the desired admin status

  try {
    // Update the admin_status for all users on the given registration date
    const query = `UPDATE users SET admin_status = ? WHERE registration_date = ?`;
    db.run(query, [newStatus, registrationDate], function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ message: 'Admin status updated successfully for all users on ' + registrationDate });
    });
  } catch (error) {
    console.error('Error updating admin status:', error);
    res.status(500).json({ error: 'Failed to update admin status' });
  }
});



// Example for in-memory database, adjust as necessary

app.get('/admin/dashboard-counts', authenticateAdminJWT, async (req, res) => {
  try {
    const getQueryPromise = (query) => new Promise((resolve, reject) => {
      db.get(query, [], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    const queries = [
      `SELECT COUNT(id) AS count FROM users`,
      `SELECT COUNT(id) AS count FROM wallets`,
      `SELECT COUNT(id) AS count FROM UpdateCases`,
      `SELECT COUNT(id) AS count FROM AlertsForm`,
      `SELECT COUNT(id) AS count FROM Appointments`,
      `SELECT COUNT(id) AS count FROM BillForm`,
      `SELECT COUNT(id) AS count FROM ClientForm`,
      `SELECT COUNT(id) AS count FROM Companies`,
      `SELECT COUNT(id) AS count FROM CourtHearing`,
      `SELECT COUNT(id) AS count FROM GroupForm`,
      `SELECT COUNT(id) AS count FROM ReviewDocForm`,
      `SELECT COUNT(id) AS count FROM TeamMembers`,
      `SELECT COUNT(id) AS count FROM chats`,
      `SELECT COUNT(id) AS count FROM ProxyForm`,
      `SELECT COUNT(id) AS count FROM InvoicesForm`
    ];

    const counts = await Promise.all(queries.map(query => getQueryPromise(query)));

    const labels = [
      'users', 'wallets', 'cases', 'alerts', 'appointments', 'bills', 'clients', 'companies',
      'courtHearings', 'groups', 'reviewDocs', 'teamMembers', 'chats', 'proxies',   'invoices'
    ];

    const results = labels.reduce((acc, label, index) => {
      acc[label] = counts[index].count;
      return acc;
    }, {});

    res.json(results);
  } catch (error) {
    console.error('Error fetching dashboard counts:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard counts' });
  }
});






app.get('/admin/proxy-acceptances', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM ProxyAcceptance ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ proxyAcceptances: rows });
  });
});

app.get('/admin/alerts', authenticateAdminJWT, async (req, res) => {
  try {
    const query = `SELECT * FROM AlertsForm ORDER BY id DESC`;
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ alerts: rows });
    });
  } catch (error) {
    console.error('Error fetching alerts:', error);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

app.get('/admin/appointments', authenticateAdminJWT, async (req, res) => {
  try {
    const query = `SELECT * FROM Appointments ORDER BY id DESC`;
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ appointments: rows });
    });
  } catch (error) {
    console.error('Error fetching appointments:', error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});


app.get('/admin/bills', authenticateAdminJWT, async (req, res) => {
  try {
    const query = `SELECT * FROM BillForm ORDER BY id DESC`;
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ bills: rows });
    });
  } catch (error) {
    console.error('Error fetching bills:', error);
    res.status(500).json({ error: 'Failed to fetch bills' });
  }
});
app.get('/admin/clients', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM ClientForm ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ clients: rows });
  });
});
app.get('/admin/groups', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM GroupForm ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ groups: rows });
  });
});

app.get('/admin/companies', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM Companies ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ companies: rows });
  });
});

app.get('/admin/court-hearings', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM CourtHearing ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ courtHearings: rows });
  });
});

app.get('/admin/review-docs', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM ReviewDocForm ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ reviewDocs: rows });
  });
});

app.get('/admin/team-members', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM TeamMembers ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ teamMembers: rows });
  });
});

app.get('/admin/chats', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM chats ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ chats: rows });
  });
});

app.get('/admin/wallets', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM wallets ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ wallets: rows });
  });
});
app.get('/admin/invoices', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM InvoicesForm ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ invoices: rows });
  });
});



/// particular case related
app.get('/admin/case-files', authenticateAdminJWT, async (req, res) => {
  try {
    const query = `SELECT * FROM CaseFiles ORDER BY id DESC`;
    db.all(query, [], (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ caseFiles: rows });
    });
  } catch (error) {
    console.error('Error fetching case files:', error);
    res.status(500).json({ error: 'Failed to fetch case files' });
  }
});
app.get('/admin/notes', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM Notes ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ notes: rows });
  });
});
app.get('/admin/case-details', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM CaseDetails ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ caseDetails: rows });
  });
});
app.get('/admin/opponent-details', authenticateAdminJWT, async (req, res) => {
  const query = `SELECT * FROM OpponentDetails ORDER BY id DESC`;
  db.all(query, [], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ opponentDetails: rows });
  });
});
////////
// async function getCasesByIds(caseIds) {
//   return new Promise((resolve, reject) => {
//     const placeholders = caseIds.map(() => '?').join(',');
//     db.all(`SELECT * FROM UpdateCases WHERE id IN (${placeholders})`, caseIds, (err, rows) => {
//       if (err) reject(err);
//       else resolve(rows);
//     });
//   });
// }
// app.get('/admin/download-selected-cases', authenticateAdminJWT, async (req, res) => {
//   const { caseIds } = req.query; // Expecting a comma-separated list of case IDs

//   if (!caseIds) {
//     return res.status(400).send('Case IDs are required');
//   }

//   const idsArray = caseIds.split(',').map(Number);
//   const casesData = await getCasesByIds(idsArray);

//   if (casesData.length === 0) {
//     return res.status(404).send('No cases found with the provided IDs');
//   }

//   let htmlContent = `
// <!DOCTYPE html>
// <html lang="en">
// <head>
//     <meta charset="UTF-8">
//     <title>Selected Cases Details</title>
//     <style>
//         body { font-family: Arial, sans-serif; padding: 20px; margin: 0; background: #ffffff; color: #333; }
//         h1 { text-align: center; color: #333; }
//         table { width: 100%; border-collapse: collapse; }
//         th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
//         th { background-color: #f2f2f2; }
//     </style>
// </head>
// <body>
//     <h1>Selected Cases Details</h1>
//     <table>
//         <thead>
//         <tr>
//         <th>Case ID</th>
//         <th>User ID</th>
//         <th>Court Type</th>
//         <th>Court</th>
//         <th>CNR No.</th>
//         <th>Case No</th>
//         <th>Case Type</th>
//         <th>Title</th>
//         <th>Court No/Desg Name</th>
//         <th>Last Hearing Date</th>
//         <th>Next Hearing Date</th>
//         <th>Final Decision Date</th>
//         <th>District Code</th>
//         <th>District Name</th>
//         <th>State Code</th>
//         <th>State Name</th>
//         <th>Specific Jurisdiction Code</th>
//         <th>Specific Jurisdiction Name</th>
//         <th>Petitioner</th>
//         <th>Respondent</th>
//         <th>Reg No</th>
//         <th>Reg Year</th>
//         <th>Filing No</th>
//         <th>Filing Year</th>
//         <th>Updated</th>
//         <th>Client</th>
//         <th>Team</th>
//         <th>Client Designation</th>
//         <th>Opponent Party Name</th>
//         <th>Lawyer Name</th>
//         <th>Mobile No</th>
//         <th>Email Id</th>
//         <th>Type</th>
//         <th>Lawyer Type</th>
//         <th>Case File</th>
//         <th>Note</th>
//     </tr>
//         </thead>
//         <tbody>`;

//   casesData.forEach(caseDetail => {
//     htmlContent += `
//     <tr>
//     <td>${caseDetail.id}</td>
//     <td>${caseDetail.user_id}</td>
//     <td>${caseDetail.court_type}</td>
//     <td>${caseDetail.court}</td>
//     <td>${caseDetail.cino}</td>
//     <td>${caseDetail.case_no}</td>
//     <td>${caseDetail.type_name}</td>
//     <td>${caseDetail.title}</td>
//     <td>${caseDetail.court_no_desg_name}</td>
//     <td>${caseDetail.date_last_list}</td>
//     <td>${caseDetail.date_next_list}</td>
//     <td>${caseDetail.date_of_decision}</td>
//     <td>${caseDetail.district_code}</td>
//     <td>${caseDetail.district_name}</td>
//     <td>${caseDetail.state_code}</td>
//     <td>${caseDetail.state_name}</td>
//     <td>${caseDetail.establishment_code}</td>
//     <td>${caseDetail.establishment_name}</td>
//     <td>${caseDetail.petparty_name}</td>
//     <td>${caseDetail.resparty_name}</td>
//     <td>${caseDetail.reg_no}</td>
//     <td>${caseDetail.reg_year}</td>
//     <td>${caseDetail.fil_no}</td>
//     <td>${caseDetail.fil_year}</td>
//     <td>${caseDetail.updated}</td>
//     <td>${caseDetail.client}</td>
//     <td>${caseDetail.team}</td>
//     <td>${caseDetail.clientDesignation}</td>
//     <td>${caseDetail.opponentPartyName}</td>
//     <td>${caseDetail.lawyerName}</td>
//     <td>${caseDetail.mobileNo}</td>
//     <td>${caseDetail.emailId}</td>
//     <td>${caseDetail.type}</td>
//     <td>${caseDetail.lawyerType}</td>
//     <td>${caseDetail.case_file}</td>
//     <td>${caseDetail.note}</td>
//     <td>${caseDetail.court}</td>
//     <td>${caseDetail.Admin_Download_Status}</td>
//   </tr>
//     `;
//   });

//   htmlContent += `</tbody></table></body></html>`;

//   // Launch Puppeteer and generate the PDF
//   const browser = await puppeteer.launch();
//   const page = await browser.newPage();
//   await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
//   const pdfBuffer = await page.pdf({ format: 'A4', printBackground: true });
//   await browser.close();

//   // Set the response headers for PDF download
//   res.setHeader('Content-Type', 'application/pdf');
//   res.setHeader('Content-Disposition', `attachment; filename="selected_cases_details.pdf"`);
//   res.send(pdfBuffer);
// });

async function getCasesByIds(caseIds) {
  return new Promise((resolve, reject) => {
    const placeholders = caseIds.map(() => '?').join(',');
    db.all(`SELECT * FROM UpdateCases WHERE id IN (${placeholders})`, caseIds, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

app.get('/admin/download-selected-cases', authenticateAdminJWT, async (req, res) => {
  const { caseIds } = req.query; // Expecting a comma-separated list of case IDs

  if (!caseIds) {
    return res.status(400).send('Case IDs are required');
  }

  const idsArray = caseIds.split(',').map(Number);
  const casesData = await getCasesByIds(idsArray);

  if (casesData.length === 0) {
    return res.status(404).send('No cases found with the provided IDs');
  }

  let htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Selected Cases Details</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; margin: 0; background: #ffffff; color: #333; }
        h1 { text-align: center; color: #333; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Selected Cases Details</h1>
    <table>
        <thead>
        <tr>
        <th>Case ID</th>
        <th>User ID</th>
        <th>Court Type</th>
        <th>Court</th>
        <th>CNR No.</th>
        <th>Case No</th>
        <th>Case Type</th>
        <th>Title</th>
        <th>Court No/Desg Name</th>
        <th>Last Hearing Date</th>
        <th>Next Hearing Date</th>
        <th>Final Decision Date</th>
        <th>District Code</th>
        <th>District Name</th>
        <th>State Code</th>
        <th>State Name</th>
        <th>Specific Jurisdiction Code</th>
        <th>Specific Jurisdiction Name</th>
        <th>Petitioner</th>
        <th>Respondent</th>
        <th>Reg No</th>
        <th>Reg Year</th>
        <th>Filing No</th>
        <th>Filing Year</th>
        <th>Updated</th>
        <th>Client</th>
        <th>Team</th>
        <th>Client Designation</th>
        <th>Opponent Party Name</th>
        <th>Lawyer Name</th>
        <th>Mobile No</th>
        <th>Email Id</th>
        <th>Type</th>
        <th>Lawyer Type</th>
        
    </tr>
        </thead>
        <tbody>`;

  // Dynamically generate table rows based on the cases data
  casesData.forEach(caseDetail => {
    htmlContent += `
    <tr>
    <td>${caseDetail.id}</td>
    <td>${caseDetail.user_id}</td>
    <td>${caseDetail.court_type}</td>
    <td>${caseDetail.court}</td>
    <td>${caseDetail.cino}</td>
    <td>${caseDetail.case_no}</td>
    <td>${caseDetail.type_name}</td>
    <td>${caseDetail.title}</td>
    <td>${caseDetail.court_no_desg_name}</td>
    <td>${caseDetail.date_last_list}</td>
    <td>${caseDetail.date_next_list}</td>
    <td>${caseDetail.date_of_decision}</td>
    <td>${caseDetail.district_code}</td>
    <td>${caseDetail.district_name}</td>
    <td>${caseDetail.state_code}</td>
    <td>${caseDetail.state_name}</td>
    <td>${caseDetail.establishment_code}</td>
    <td>${caseDetail.establishment_name}</td>
    <td>${caseDetail.petparty_name}</td>
    <td>${caseDetail.resparty_name}</td>
    <td>${caseDetail.reg_no}</td>
    <td>${caseDetail.reg_year}</td>
    <td>${caseDetail.fil_no}</td>
    <td>${caseDetail.fil_year}</td>
    <td>${caseDetail.updated}</td>
    <td>${caseDetail.client}</td>
    <td>${caseDetail.team}</td>
    <td>${caseDetail.clientDesignation}</td>
    <td>${caseDetail.opponentPartyName}</td>
    <td>${caseDetail.lawyerName}</td>
    <td>${caseDetail.mobileNo}</td>
    <td>${caseDetail.emailId}</td>
    <td>${caseDetail.type}</td>
    <td>${caseDetail.lawyerType}</td>
    
    
  </tr>
    `;
  });

  htmlContent += `</tbody></table></body></html>`;

  // Launch Puppeteer and generate the PDF with adjusted settings for a landscape layout
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.setContent(htmlContent, { waitUntil: 'networkidle0' });
  const pdfBuffer = await page.pdf({
    format: 'A2', // or 'A3' for a larger size
    landscape: true, // Use landscape orientation to fit more content horizontally
    printBackground: true
  });
  await browser.close();

  // Set the response headers for PDF download
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="selected_cases_details.pdf"`);
  res.send(pdfBuffer);
});


app.post('/admin/update-cases-status', authenticateAdminJWT, async (req, res) => {
  // Expecting caseIds as an array of case IDs and newStatus as the new status value
  const { caseIds, newStatus } = req.body; 

  if (!caseIds || caseIds.length === 0) {
    return res.status(400).json({ error: 'Case IDs are required' });
  }

  try {
    // Use a transaction if your DB supports it, to ensure all updates succeed or fail as one atomic operation
    const placeholders = caseIds.map(() => '?').join(',');
    const query = `UPDATE UpdateCases SET Admin_Download_Status = ? WHERE id IN (${placeholders})`;

    // Assuming db.run can be promisified or using a library that supports promises
    // Adjust based on your specific database library's syntax
    await db.run(query, [newStatus, ...caseIds], function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.json({ message: `Admin download status updated successfully for selected cases.` });
    });
  } catch (error) {
    console.error('Error updating cases status:', error);
    res.status(500).json({ error: 'Failed to update cases status' });
  }
});





// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password, name, mobile, lawyerType, experience, age } = req.body;
    if (!username || !password || !name || !mobile || !lawyerType || !experience || !age) {
      return res.status(400).json({ error: 'Name, mobile, email, lawyerType, experience, age and password are required' });
    }

    const avatarUrl = `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random&color=fff`;


    const hashedPassword = await bcrypt.hash(password, 10);
    const emailVerificationToken = crypto.randomBytes(20).toString('hex');
    const trialStartDate = new Date().toISOString().split('T')[0];

    db.run('INSERT INTO users (name, lawyerType, experience, age, mobile, username, hashed_password, avatar_url, email_verification_token, trial_start_date, registration_date) VALUES (?,?,?,?,?,?, ?, ?, ?, ?, DATE("now"))',
      [name, lawyerType, experience, age, mobile, username, hashedPassword, avatarUrl, emailVerificationToken, trialStartDate], function (err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        const userId = this.lastID;
        db.run('INSERT INTO wallets (user_id, balance) VALUES (?, ?)', [userId, 0], function (err) {
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
  db.run('UPDATE wallets SET balance = balance + ? WHERE user_id = ?', [amount, userId], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: 'Funds added successfully' });
  });
});


app.post('/wallet/transfer-to-bank', async (req, res) => {
  const { amount, accountNumber, accountName, ifsc, name: beneficiaryName, email, contactNumber } = req.body;

  console.log("Received payload for transfer:", req.body);

  try {
    if (!beneficiaryName) {
      throw new Error('Beneficiary name is required but was not provided.');
    }

    // Step 1: Create Contact in Razorpay
    const contactResponse = await axios.post('https://api.razorpay.com/v1/contacts', {
      name: beneficiaryName,
      email: email,
      contact: contactNumber,
      type: "customer",
    }, { auth: razorpayAuth });

    console.log("Contact created:", contactResponse.data);
    const contactId = contactResponse.data.id;

    // Step 2: Create a Fund Account for the Contact
    const fundAccountResponse = await axios.post('https://api.razorpay.com/v1/fund_accounts', {
      contact_id: contactId,
      account_type: "bank_account",
      bank_account: {
        name: accountName,
        account_number: accountNumber,
        ifsc: ifsc,
      },
    }, { auth: razorpayAuth });

    console.log("Fund account created:", fundAccountResponse.data);
    const fundAccountId = fundAccountResponse.data.id;

    // Step 3: Create a Payout
    const payoutAmount = parseInt(amount, 10) * 100;
    const payoutResponse = await axios.post('https://api.razorpay.com/v1/payouts', {
      account_number: '2323230005927739',
      fund_account_id: fundAccountId,
      amount: payoutAmount,
      currency: "INR",
      mode: "IMPS",
      purpose: "payout",
      // description: "Wallet to bank transfer",
    }, { auth: razorpayAuth });

    console.log("Payout created:", payoutResponse.data);

    // Here, you'd normally proceed with deducting the amount from the user's wallet
    // and other business logic related to your application

    res.json({ success: true, message: "Transfer successfully initiated", data: payoutResponse.data });
  } catch (error) {
    console.error('Error in transfer:', error.response ? error.response.data : error.message);
    res.status(500).json({
      success: false,
      message: "Failed to initiate transfer",
      error: error.response ? error.response.data.error : error.message
    });
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


app.get('/validate-session', authenticateJWT, (req, res) => {
  // If the middleware doesn't reject the request, the session is still valid.
  res.json({ valid: true });
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT id, username, hashed_password, is_verified, email_verification_token FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (!user.is_verified) {
      // User's email is not verified, resend verification email
      sendVerificationEmail(username, user.email_verification_token);

      return res.status(401).json({ error: 'Email not verified. A new verification email has been sent to your email address. Please verify your email.' });
    }


    const validPassword = await bcrypt.compare(password, user.hashed_password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const newSessionId = crypto.randomBytes(20).toString('hex');

    const now = new Date().toISOString();
    db.run('UPDATE users SET current_session_id = ?, is_online = TRUE, last_seen = ? WHERE id = ?', [newSessionId, now, user.id], updateErr => {
      if (updateErr) {
        // Optionally handle error
        console.error('Failed to update user status:', updateErr.message);
      }
      const token = jwt.sign({ id: user.id, username: user.username, sessionId: newSessionId }, secretKey);
      // Respond with the token and session ID
      res.json({ token, sessionId: newSessionId });
      console.log('user token', token)
    });
    
  });
});

app.post('/logout', authenticateJWT, (req, res) => {
  console.log('Logout request received'); // Log when a request is received

  // Check if req.user is defined
  if (!req.user) {
    console.log('req.user is undefined. Token may be missing or invalid.');
    return res.status(401).json({ error: 'Unauthorized: Token missing or invalid.' });
  }

  console.log('User ID from token:', req.user.id); // Log the user ID extracted from the token

  const userId = req.user.id;
  const now = new Date().toISOString(); // For updating last_seen

  // Update the user's online status and last_seen timestamp
  db.run('UPDATE users SET is_online = FALSE, last_seen = ? WHERE id = ?', [now, userId], (err) => {
    if (err) {
      console.error('Failed to update user status on logout:', err.message);
      return res.status(500).json({ error: 'An error occurred while logging out.' });
    }
    console.log(`Updated user ${userId} status to offline.`);
    res.status(200).json({ message: 'Logged out successfully.' });
  });
});


app.get('/profile', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.get('SELECT id,username, name, mobile, lawyerType, experience, age,avatar_url FROM users WHERE id = ?', [userId], (err, user) => {
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

  // Check if mobile number already exists for another user
  if (mobile) {
    const checkMobileQuery = 'SELECT id FROM users WHERE mobile = ? AND id != ?';
    db.get(checkMobileQuery, [mobile, userId], (err, row) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (row) {
        return res.status(409).json({ error: 'Mobile number already exists' });
      } else {
        // Proceed with update if mobile number does not exist
        updateUserProfile(req, res, userId, { name, mobile, lawyerType, experience, age });
      }
    });
  } else {
    // Proceed with update if mobile not provided
    updateUserProfile(req, res, userId, { name, mobile, lawyerType, experience, age });
  }
});

function updateUserProfile(req, res, userId, { name, mobile, lawyerType, experience, age }) {
  const updateFields = [];
  const updateValues = [];

  if (name) {
    updateFields.push('name = ?');
    updateValues.push(name);

    const newAvatarUrl = `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random&color=fff`;
    updateFields.push('avatar_url = ?');
    updateValues.push(newAvatarUrl);
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
}


// Endpoint to initiate password reset
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const token = crypto.randomBytes(20).toString('hex');
  const resetTokenExpires = Date.now() + 3600000; // 1 hour from now

  db.run('UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE username = ?', [token, resetTokenExpires, email], function (err) {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }

    // const resetLink = `http://localhost:3000/reset-password/${token}`;
    // Send email with resetLink here using your sendVerificationEmail function or similar
    sendForgotPasswordEmail(email, token);

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
    [hashedPassword, token, Date.now()], function (err) {
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
app.post('/api/subscribe', authenticateJWT, async (req, res) => {
  const userId = req.user.id; // Extract user ID from JWT
  console.log("User ID:", userId);

  const { subscriptionType } = req.body; // This should be either 'monthly' or 'annual'
  console.log("Received subscription type:", subscriptionType);

  const currentDate = new Date();
  let subscriptionEndDate = new Date(currentDate); // Clone the current date to avoid mutation

  if (subscriptionType === 'monthly') {
    subscriptionEndDate.setMonth(subscriptionEndDate.getMonth() + 1);
  } else if (subscriptionType === 'annual') {
    subscriptionEndDate.setFullYear(subscriptionEndDate.getFullYear() + 1);
  }


  db.run('UPDATE users SET subscription_end_date = ? WHERE id = ?', [subscriptionEndDate.toISOString().split('T')[0], userId], function (err) {
    if (err) {
      console.error("Error updating subscription end date:", err);
      return res.status(500).json({ error: 'Failed to update subscription end date' });
    }
    return res.json({ message: 'Subscription updated successfully.' });
  });
})


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


//chatbot code
app.get('/generate-presigned-url', authenticateJWT, async (req, res) => {
  const { fileName } = req.query;
  console.log('Generating pre-signed URL for:', fileName);

  const command = new PutObjectCommand({
    Bucket: process.env.AWS_BUCKET_NAME,
    Key: fileName,
    ContentType: 'application/pdf',
    // ACL: 'public-read',
  });

  try {
    const url = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
    console.log('Pre-signed URL generated successfully:', url);
    res.json({ url });
  } catch (error) {
    console.error('Error generating pre-signed URL:', error);
    res.status(500).send('Error generating pre-signed URL');
  }
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
    'SELECT id, title, startDate, completionDate, caseTitle, caseType, assignFrom, assignTo FROM AlertsForm WHERE user_id = ? ORDER BY id DESC',
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

// chat box application
app.get('/searchUsers', authenticateJWT, checkAccess, async (req, res) => {
  try {
    const { query } = req.query; // Get the search query from URL parameters
    const userId = req.user.id; // Assuming req.user.id contains the current user's ID

    // SQL query that searches for users by name or username but excludes the current user
    const sql = `SELECT * FROM users WHERE (name LIKE ? OR username LIKE ?) AND id <> ?`;
    const params = [`%${query}%`, `%${query}%`, userId];

    db.all(sql, params, (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({
        message: 'Success',
        data: rows
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});


app.post('/api/chats', authenticateJWT, checkAccess, async (req, res) => {
  try {
    const userId = req.user.id; // Current user's ID
    const selectedUserId = req.body.selectedUserId; // User selected from search

    // Check if a chat session already exists
    const findChatSql = `
      SELECT * FROM chats
      WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?);
    `;

    db.get(findChatSql, [userId, selectedUserId, selectedUserId, userId], async (err, row) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (row) {
        // Chat exists, now fetch selected user's details
        const userDetails = await fetchUserDetails(selectedUserId);
        res.json({
          message: 'Chat session retrieved successfully',
          chatId: row.id,
          user: userDetails // Include user details in the response
        });
      } else {
        // No chat exists, create a new chat session
        const insertChatSql = `INSERT INTO chats (user1_id, user2_id) VALUES (?, ?);`;
        db.run(insertChatSql, [userId, selectedUserId], async function (err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          const userDetails = await fetchUserDetails(selectedUserId);
          // Return the new chat ID along with selected user's details
          res.json({
            message: 'Chat session created successfully',
            chatId: this.lastID,
            user: userDetails // Include user details
          });
        });
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

// Function to fetch user details by ID
async function fetchUserDetails(userId) {
  return new Promise((resolve, reject) => {
    const sql = `SELECT id, name, username, avatar_url FROM users WHERE id = ?`;
    db.get(sql, [userId], (err, row) => {
      if (err) {
        reject(err);
      } else {
        resolve(row); // Return the user details
      }
    });
  });
}
app.get('/api/chats', authenticateJWT, checkAccess, async (req, res) => {
  try {
    const userId = req.user.id; // Get current user's ID from JWT

    // SQL query to fetch chats and count of unread messages
    const sql = `
      SELECT chats.id, chats.user1_id, chats.user2_id, 
      u1.name AS user1_name, u1.avatar_url AS user1_avatar_url, u1.is_online AS user1_online, 
      u2.name AS user2_name, u2.avatar_url AS user2_avatar_url, u2.is_online AS user2_online,
      (SELECT COUNT(*) FROM messages WHERE chat_id = chats.id AND sender_id != ? AND is_read = 0) AS unread_messages_count
      FROM chats
      JOIN users u1 ON chats.user1_id = u1.id
      JOIN users u2 ON chats.user2_id = u2.id
      WHERE chats.user1_id = ? OR chats.user2_id = ?;
    `;

    // Execute the SQL query
    db.all(sql, [userId, userId, userId], (err, rows) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      // Transform rows to include only the relevant details
      const chats = rows.map(row => {
        const otherUser = row.user1_id === userId ?
          { id: row.user2_id, name: row.user2_name, avatarUrl: row.user2_avatar_url, isOnline: row.user2_online, unreadMessagesCount: row.unread_messages_count } :
          { id: row.user1_id, name: row.user1_name, avatarUrl: row.user1_avatar_url, isOnline: row.user1_online, unreadMessagesCount: row.unread_messages_count };
        return { chatId: row.id, otherUser };
      });

      res.json({
        message: 'Success',
        data: chats
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});


// This route now handles both text messages and file uploads
app.post('/api/messages', authenticateJWT, upload.single('file'), checkAccess, async (req, res) => {
  const { chatId, content } = req.body; // Text content of the message
  const senderId = req.user.id; // Sender's user ID from JWT
  const filePath = req.file ? req.file.filename : null; // File path if a file is uploaded

  if (!chatId || (!content && !filePath)) {
    return res.status(400).json({ error: 'Chat ID and either content or a file are required' });
  }

  try {
    const sql = `INSERT INTO messages (chat_id, sender_id, content, file_path) VALUES (?, ?, ?, ?)`;
    const params = [chatId, senderId, content, filePath];

    db.run(sql, params, function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Message sent successfully', messageId: this.lastID });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});



app.get('/api/messages/:chatId', authenticateJWT, checkAccess, async (req, res) => {
  const { chatId } = req.params;
  // Assuming `db` is your database connection
  try {
    const sql = `SELECT * FROM messages WHERE chat_id = ? ORDER BY created_at ASC`;
    const params = [chatId];
    db.all(sql, params, (err, messages) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ messages });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/currentUser', authenticateJWT, async (req, res) => {
  try {
    // Assuming req.user is populated from the authenticateJWT middleware
    const userId = req.user.id; // Or however you store the user ID in the req.user object

    // You might want to fetch more details from the database, but here we just return the ID
    res.json({ userId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/messages/read', authenticateJWT, checkAccess, async (req, res) => {
  const { chatId } = req.body;
  const userId = req.user.id; // Current user's ID

  try {
    const sql = `UPDATE messages SET is_read = 1 WHERE chat_id = ? AND sender_id != ?`;
    db.run(sql, [chatId, userId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Messages marked as read' });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});


app.get('/api/messages/unread/global-count', authenticateJWT, checkAccess, async (req, res) => {
  const userId = req.user.id; // Extract user ID from JWT token

  console.log(`Fetching global unread count for user ID: ${userId}`); // Log before executing the query

  const sql = `
    SELECT COUNT(*) AS globalUnreadCount
    FROM messages
    JOIN chats ON messages.chat_id = chats.id
    WHERE (chats.user1_id = ? OR chats.user2_id = ?)
    AND messages.sender_id != ?
    AND messages.is_global_read = 0;
  `;

  db.get(sql, [userId, userId, userId], (err, result) => {
    if (err) {
      console.error(`Error fetching global unread count for user ID: ${userId}`, err); // Log any error
      return res.status(500).json({ error: 'Internal server error' });
    }
    console.log(`Global unread count for user ID: ${userId} is ${result.globalUnreadCount}`); // Log the result
    res.json({ globalUnreadCount: result.globalUnreadCount });
  });
});

app.patch('/api/messages/mark-global-read', authenticateJWT, checkAccess, async (req, res) => {
  const userId = req.user.id; // Extract user ID from JWT token

  const sql = `
    UPDATE messages
    SET is_global_read = 1
    WHERE id IN (
      SELECT messages.id
      FROM messages
      JOIN chats ON messages.chat_id = chats.id
      WHERE (chats.user1_id = ? OR chats.user2_id = ?)
      AND messages.sender_id != ?
      AND messages.is_global_read = 0
    );
  `;

  db.run(sql, [userId, userId, userId], (err) => {
    if (err) {
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json({ message: 'Messages marked as globally read' });
  });
});






app.post('/appointments', authenticateJWT, (req, res) => {
  try {
    const { title, caseTitle, caseType, appointmentDate, contactPerson, location, startTime, endTime, email } = req.body;
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


app.get('/alerts/download-pdf/:alertId', authenticateJWT, async (req, res) => {
  try {
    const { alertId } = req.params;

    // Retrieve alert data from your database
    const alertData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM AlertsForm WHERE id = ? AND user_id = ?',
        [alertId, req.user.id],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!alertData) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    // Define the HTML content for PDF generation
    const htmlContent = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Alert Data</title>
        <style>
            body {
                font-family: 'Times New Roman', Times, serif;
                padding: 40px;
                background: #fff;
                color: #000;
                margin: 0;
            }
            .container {
                max-width: 700px;
                margin: 20px auto;
                border: 1px solid #ddd;
                padding: 20px;
            }
            h1 {
                font-size: 24px;
                text-align: center;
                color: #333;
                margin-bottom: 30px;
            }
            p {
                font-size: 16px;
                margin: 10px 0 20px;
            }
            p span.label {
                font-weight: bold;
                display: inline-block;
                min-width: 150px;
                color: #555;
            }
            .footer {
                text-align: center;
                margin-top: 40px;
                font-size: 14px;
                color: #666;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Alert Data</h1>
            <p><span class="label">Title:</span> ${alertData.title}</p>
            <p><span class="label">Case Title:</span> ${alertData.caseTitle}</p>
            <p><span class="label">Case Type:</span> ${alertData.caseType}</p>
            <p><span class="label">Start Date:</span> ${alertData.startDate}</p>
            <p><span class="label">Completion Date:</span> ${alertData.completionDate}</p>
            <p><span class="label">Assign From:</span> ${alertData.assignFrom}</p>
            <p><span class="label">Assign To:</span> ${alertData.assignTo}</p>
            <div class="footer">
                Confidential Document | [LAWFAX]
            </div>
        </div>
    </body>
    </html>`;

    // Launch Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Set the content of the page to your HTML
    await page.setContent(htmlContent, {
      waitUntil: 'networkidle0'
    });

    // Create a PDF buffer
    const pdfBuffer = await page.pdf({
      format: 'A4',
      printBackground: true
    });

    // Close the browser
    await browser.close();

    // Set the response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Alert_${alertId}.pdf`);

    // Send the PDF in the response
    res.send(pdfBuffer);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
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
app.use('/uploads', express.static(path.join(__dirname, './Db-data/uploads')));


//get endpoint to render teammember form data on edit form
app.get('/dashboard/teammemberform/edit', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT id,image, fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno FROM TeamMembers WHERE user_id = ? ORDER BY id DESC',
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
    db.run(updateQuery, [imagePath, fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno, memberId, userId], (updateErr) => {
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

      db.run(insertQuery, [imagePath, fullName, email, designation, address, state, city, zipCode, selectedGroup, selectedCompany, mobileno, userId], function (insertErr) {
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

    // Retrieve team member data from the database
    const memberData = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM TeamMembers WHERE id = ? AND user_id = ?',
        [memberId, req.user.id],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!memberData) {
      return res.status(404).json({ error: 'Team member not found' });
    }

    // Define an HTML template for your PDF content
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Team Member Data</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            padding: 40px;
            background: #f4f4f9;
            color: #333;
            margin: 0;
            line-height: 1.6;
        }
        .container {
            max-width: 800px;
            margin: 20px auto;
            background: #ffffff;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #0056b3;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #0056b3;
        }
        p {
            background: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            border-left: 5px solid #0056b3;
            margin: 10px 0;
            font-size: 16px;
        }
        p span {
            font-weight: bold;
            color: #0056b3;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            font-size: 14px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Team Member Data</h1>
        <p><span>Full Name:</span> ${memberData.fullName}</p>
        <p><span>Email:</span> ${memberData.email}</p>
        <p><span>Mobile Number:</span> ${memberData.mobileno}</p>
        <p><span>Designation:</span> ${memberData.designation}</p>
        <p><span>Address:</span>  ${memberData.address}</p>
        <p><span>State:</span>  ${memberData.state}</p>
        <p><span>City:</span> ${memberData.city}</p>
        <p><span>Zip Code:</span> ${memberData.zipCode}</p>
        <p><span>Selected Group:</span>  ${memberData.selectedGroup}</p>
        <div class="footer">
            © 2024 LAWFAX. All rights reserved.
        </div>
    </div>
</body>
</html>
    `;

    // Launch Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Set the content of the page to your HTML
    await page.setContent(htmlContent, {
      waitUntil: 'networkidle0'
    });

    // Create a PDF buffer
    const pdfBuffer = await page.pdf({
      format: 'A4',
      printBackground: true
    });

    // Close the browser
    await browser.close();

    // Set the response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=TeamMember_${memberData.id}.pdf`);

    // Send the PDF buffer in the response
    res.send(pdfBuffer);

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
      title, client, email, mobile, date, time, roomNo, assignedBy, assignedTo, followUpDate, followUpTime, description, } = req.body;

    const userId = req.user.id;

    if (!title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    db.run(
      'INSERT INTO AppointmentForm (title, client, email, mobile, date, time, roomNo, assignedBy, assignedTo, followUpDate, followUpTime, description, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        title, client, email, mobile, date, time, roomNo, assignedBy, assignedTo, followUpDate, followUpTime, description, userId,
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
    'SELECT id, billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc FROM BillForm WHERE user_id = ? ORDER BY id DESC',
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
      billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc } = req.body;

    const userId = req.user.id;

    if (!billNumber || !title) {
      return res.status(400).json({ error: 'Bill number and title are required' });
    }
    db.run(
      'INSERT INTO BillForm (billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [
        billNumber, title, currentDate, dateFrom, dateTo, fullAddress, billingType, totalHours, noOfHearings, totalAmount, amount, taxType, taxPercentage, totalAmountWithTax, description, addDoc, userId,
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

    // Retrieve bill data from the database
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

    // Define the HTML template for your PDF content
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bill Data</title>
  <style>
    body {
      font-family: 'Arial', sans-serif;
      background-color: #f5f5f5;
      margin: 0;
      padding: 20px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background-color: #fff;
      margin-top: 20px;
    }
    th, td {
      padding: 12px;
      border: 1px solid #ddd;
      text-align: left;
      font-size: 16px;
    }
    th {
      background-color: #007BFF;
      color: #ffffff;
    }
    .header {
      background-color: #28a745;
      color: #fff;
      font-size: 24px;
      text-align: center;
      padding: 10px 0;
      margin-bottom: 20px;
      border-radius: 4px;
    }
    .total-row, .tax-row {
      background-color: #ffc107;
      color: #212529;
      font-weight: bold;
    }
    .highlight {
      background-color: #17a2b8;
      color: #fff;
    }
    .description {
      background-color: #6c757d;
      color: #fff;
      font-style: italic;
    }
  </style>
</head>
<body>
  <div class="header">Bill Data</div>
  <table>
    <tr><th>Field</th><th>Details</th></tr>
    <tr><td>Bill Number</td><td>${billData.billNumber}</td></tr>
    <tr><td>Title</td><td>${billData.title}</td></tr>
    <tr><td>Current Date</td><td>${billData.currentDate}</td></tr>
    <tr><td>Date From</td><td>${billData.dateFrom}</td></tr>
    <tr><td>Date To</td><td>${billData.dateTo}</td></tr>
    <tr><td>Full Address</td><td>${billData.fullAddress}</td></tr>
    <tr><td>Billing Type</td><td>${billData.billingType}</td></tr>
    <tr><td>Total Hours</td><td>${billData.totalHours}</td></tr>
    <tr><td>No. of Hearings</td><td>${billData.noOfHearings}</td></tr>
    <tr class="total-row"><td>Total Amount</td><td>${billData.totalAmount}</td></tr>
    <tr><td>Amount</td><td>${billData.amount}</td></tr>
    <tr class="tax-row"><td>Tax Type</td><td>${billData.taxType}</td></tr>
    <tr class="tax-row"><td>Tax Percentage</td><td>${billData.taxPercentage}</td></tr>
    <tr class="highlight"><td>Total Amount With Tax</td><td>${billData.totalAmountWithTax}</td></tr>
    <tr class="description"><td>Description</td><td>${billData.description}</td></tr>
  </table>
</body>
</html>
    `;

    // Launch Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Set the HTML content for the page
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

    // Generate the PDF from the page content
    const pdfBuffer = await page.pdf({
      format: 'A4',
      printBackground: true,
    });

    // Close the browser
    await browser.close();

    // Set the response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Bill_${billId}.pdf`);

    // Send the PDF buffer in the response
    res.send(pdfBuffer);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});


function runQuery(query, params) {
  return new Promise((resolve, reject) => {
    db.run(query, params, function (err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });
  });
}
// app.post('/updatecase', authenticateJWT, async (req, res) => {
//   const casesArray = req.body.cases;
//   const userId = req.user.id; // Assuming you have a way to extract this from the authenticated user

//   try {
//     let lastId;
//     for (const caseData of casesArray) {
//       const query = `
//         INSERT INTO UpdateCases (
//           cino, case_no, court_no_desg_name, date_last_list, date_next_list,
//           date_of_decision, district_code, district_name, establishment_code,
//           establishment_name, fil_no, fil_year, petparty_name, note, reg_no,
//           reg_year, resparty_name, state_code, state_name, type_name, updated, user_id
//         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//       `;
//       // Prepare parameters for the query from caseData and userId
//       const params = [
//         caseData.cino, caseData.case_no, caseData.court_no_desg_name, caseData.date_last_list, caseData.date_next_list,
//         caseData.date_of_decision, caseData.district_code, caseData.district_name, caseData.establishment_code,
//         caseData.establishment_name, caseData.fil_no, caseData.fil_year, caseData.petparty_name, caseData.note, caseData.reg_no,
//         caseData.reg_year, caseData.resparty_name, caseData.state_code, caseData.state_name, caseData.type_name, caseData.updated, userId
//       ];

//       lastId = await runQuery(query, params);
//     }

//     if (lastId !== undefined) {
//       res.json({ caseId: lastId, message: 'Case added successfully' });
//     } else {
//       res.status(400).json({ error: 'Failed to add the case' });
//     }
//   } catch (error) {
//     console.error('Error in /updatecase endpoint:', error);

//     if (error.code === 'SQLITE_CONSTRAINT' && error.message.includes('UNIQUE constraint failed: UpdateCases.cino')) {
//       res.status(400).json({ error: 'A case with the given CNR No. already exists.' });
//     } else {
//       res.status(500).json({ error: 'Internal Server Error' });
//     }
//   }
// });

function runQuery(query, params) {
  return new Promise((resolve, reject) => {
    db.run(query, params, function (err) {
      if (err) {
        console.error("Database Error:", err); // Debugging
        reject(err);
      } else {
        console.log("Last Inserted ID:", this.lastID); // Debugging
        resolve(this.lastID);
      }
    });
  });
}

app.post('/updatecase', authenticateJWT, async (req, res) => {
  const casesArray = req.body.cases;
  const userId = req.user.id;

  let addedCases = []; // Store lastIDs of successfully added cases
  let skippedCases = 0; // Count skipped cases due to existing cino

  for (const caseData of casesArray) {
    const query = `
      INSERT INTO UpdateCases (
        cino,court, case_no, court_no_desg_name, date_last_list, date_next_list,
        date_of_decision, district_code, district_name, establishment_code,
        establishment_name, fil_no, fil_year, petparty_name, note, reg_no,
        reg_year, resparty_name, state_code, state_name, type_name, updated, user_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      caseData.cino, caseData.court, caseData.case_no, caseData.court_no_desg_name, caseData.date_last_list, caseData.date_next_list,
      caseData.date_of_decision, caseData.district_code, caseData.district_name, caseData.establishment_code,
      caseData.establishment_name, caseData.fil_no, caseData.fil_year, caseData.petparty_name, caseData.note, caseData.reg_no,
      caseData.reg_year, caseData.resparty_name, caseData.state_code, caseData.state_name, caseData.type_name, caseData.updated, userId
    ];

    try {
      const lastId = await runQuery(query, params);
      addedCases.push(lastId);
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT' && error.message.includes('UNIQUE constraint failed: UpdateCases.cino')) {
        skippedCases++;
        continue;
      } else {
        console.error('Error adding case with cino:', caseData.cino, error);
      }
    }
  }

  res.json({
    message: `Cases processed. Added: ${addedCases.length}, Skipped: ${skippedCases}`,
    addedCaseIds: addedCases
  });
});
app.post('/uploadcasefile', authenticateJWT, upload.single('case_file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  const { caseId } = req.body; // Ensure 'caseId' is sent with FormData
  const userId = req.user.id; // User ID from JWT
  const filePath = req.file.filename; // Assuming you want the path where the file is saved

  // SQL query to insert the new file path into CaseFiles
  const insertQuery = `
    INSERT INTO CaseFiles (case_id, file_path, user_id)
    VALUES (?, ?, ?)
  `;

  db.run(insertQuery, [caseId, filePath, userId], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    return res.json({ message: 'Case file added successfully', filePath });
  });
});
app.get('/case-files/:caseId', authenticateJWT, async (req, res) => {
  const { caseId } = req.params; // Extract caseId from URL parameters
  const userId = req.user.id; // User ID from JWT token, assuming authenticateJWT adds this

  // SQL query to select all files for the specified caseId and userId
  const selectQuery = `
    SELECT * FROM CaseFiles
    WHERE case_id = ? AND user_id = ?
    ORDER BY id DESC
  `;

  db.all(selectQuery, [caseId, userId], (err, files) => {
    if (err) {
      console.error('Error fetching case files:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (files.length === 0) {
      // No files found for this case
      return res.status(404).json({ error: 'No files found for this case' });
    }
    // Return the list of files
    res.json(files);
  });
});
app.get('/download/:filename', authenticateJWT, (req, res) => {
  const { filename } = req.params;
  const directoryPath = path.join(__dirname, './Db-data/uploads'); // Adjust 'uploads' to your files directory
  const filePath = path.join(directoryPath, filename);

  // Validate file exists
  if (fs.existsSync(filePath)) {
    res.download(filePath, filename, (err) => {
      if (err) {
        console.error(err);
        res.status(500).send("Could not download the file.");
      }
    });
  } else {
    res.status(404).send("File not found.");
  }
});

app.delete('/delete-document/:documentId', authenticateJWT, async (req, res) => {
  const { documentId } = req.params;
  const userId = req.user.id; // User ID from JWT token

  // First, find the file to get its filename (for deletion from the filesystem)
  const selectQuery = `SELECT * FROM CaseFiles WHERE id = ? AND user_id = ?`;

  db.get(selectQuery, [documentId, userId], (err, file) => {
    if (err) {
      console.error('Error fetching document:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (!file) {
      return res.status(404).json({ error: 'Document not found' });
    }

    // If file is found, delete it from the database
    const deleteQuery = `DELETE FROM CaseFiles WHERE id = ? AND user_id = ?`;

    db.run(deleteQuery, [documentId, userId], function (err) {
      if (err) {
        console.error('Error deleting document:', err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Document not found' });
      }

      // Optionally, delete the file from the filesystem
      const filePath = path.join(__dirname, './Db-data/uploads', file.file_path);
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error('Error deleting file from filesystem:', err);
          // Even if file deletion fails, inform that database entry was removed
          return res.json({ message: 'Document deleted from database, but file deletion failed' });
        }
        res.json({ message: 'Document deleted successfully' });
      });
    });
  });
});

app.post('/note', authenticateJWT, async (req, res) => {
  const { caseId, note } = req.body;
  console.log(req.body); // Add this line in your '/note' endpoint to log the request body


  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  const insertQuery = `
    INSERT INTO Notes (case_id, note)
    VALUES (?, ?)
  `;

  const userId = req.user.id;

  // Check if the case exists and belongs to the user before adding a note
  const caseExistsQuery = `SELECT 1 FROM UpdateCases WHERE id = ? AND user_id = ? LIMIT 1`;

  db.get(caseExistsQuery, [caseId, userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Case not found or does not belong to the user' });
    }

    // If case exists, insert the note
    db.run(insertQuery, [caseId, note], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json({ message: 'Note added successfully' });
    });
  });
});

app.get('/notes/:caseId', authenticateJWT, async (req, res) => {
  const { caseId } = req.params;

  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  const userId = req.user.id; // Assuming you want to ensure that only the notes belonging to the logged-in user are fetched

  const selectQuery = `
    SELECT * FROM Notes
    WHERE case_id = ? AND EXISTS (
      SELECT 1 FROM UpdateCases WHERE id = ? AND user_id = ?
    )
    ORDER BY id DESC
  `;

  db.all(selectQuery, [caseId, caseId, userId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'No notes found for this case or case does not belong to the user' });
    }
    res.json(rows); // Send back the array of notes
  });
});
app.delete('/note/:noteId', authenticateJWT, async (req, res) => {
  const { noteId } = req.params;
  const userId = req.user.id; // Assuming the note should only be deletable by the user who owns it

  // First, check if the note exists and belongs to the logged-in user
  const noteExistsQuery = `
    SELECT 1 FROM Notes
    JOIN UpdateCases ON Notes.case_id = UpdateCases.id
    WHERE Notes.id = ? AND UpdateCases.user_id = ?
    LIMIT 1
  `;

  db.get(noteExistsQuery, [noteId, userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Note not found or does not belong to the user' });
    }

    // If the note exists and belongs to the user, proceed with deletion
    const deleteQuery = `
      DELETE FROM Notes
      WHERE id = ?
    `;

    db.run(deleteQuery, [noteId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to delete note' });
      }
      if (this.changes === 0) {
        // No rows were deleted, this should not happen since we already checked the note exists
        return res.status(404).json({ error: 'Note not found' });
      }
      res.json({ message: 'Note deleted successfully' });
    });
  });
});


app.post('/person', authenticateJWT, async (req, res) => {
  const { caseId, client, team, type, lawyerType } = req.body;

  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  // Ensure the case exists and belongs to the user
  const caseExistsQuery = `SELECT 1 FROM UpdateCases WHERE id = ? AND user_id = ? LIMIT 1`;
  const userId = req.user.id;

  db.get(caseExistsQuery, [caseId, userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Case not found or does not belong to the user' });
    }

    // Insert data into CaseDetails table
    const insertQuery = `
      INSERT INTO CaseDetails (case_id, client, team, type, lawyerType, user_id)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.run(insertQuery, [caseId, client, team, type, lawyerType, userId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      return res.json({ message: 'Case detail added successfully' });
    });
  });
});
app.get('/case-details/:caseId', authenticateJWT, async (req, res) => {

  const { caseId } = req.params;
  const userId = req.user.id; // Assuming the middleware has already attached the user ID to the request
  console.log("Fetching case details for:", req.params.caseId, "User ID:", req.user.id);

  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  const selectQuery = `
    SELECT * FROM CaseDetails
    WHERE case_id = ? AND user_id = ?
    ORDER BY id DESC
  `;

  db.all(selectQuery, [caseId, userId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (rows.length === 0) {
      return res.status(404).json({ error: 'No details found for this case or case does not belong to the user' });
    }
    res.json(rows); // Send back the array of case details
  });
});

app.delete('/case-detail/:detailId', authenticateJWT, async (req, res) => {
  const { detailId } = req.params; // The ID of the detail to be deleted
  const userId = req.user.id; // User ID from the JWT middleware

  // First, verify the detail exists and belongs to the user
  const verifyQuery = `
    SELECT 1 FROM CaseDetails
    JOIN UpdateCases ON CaseDetails.case_id = UpdateCases.id
    WHERE CaseDetails.id = ? AND UpdateCases.user_id = ?
    LIMIT 1
  `;

  db.get(verifyQuery, [detailId, userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Detail not found or not authorized to delete' });
    }

    // If verification is successful, proceed to delete the detail
    const deleteQuery = `DELETE FROM CaseDetails WHERE id = ?`;

    db.run(deleteQuery, [detailId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to delete case detail' });
      }
      if (this.changes === 0) {
        // No detail was deleted, this should not happen as we've already verified its existence
        return res.status(404).json({ error: 'Detail not found' });
      }
      res.json({ message: 'Case detail deleted successfully' });
    });
  });
});

app.post('/opponent', authenticateJWT, async (req, res) => {
  const { caseId, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId } = req.body;

  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  // Check if the case exists and belongs to the user before adding opponent details
  const caseExistsQuery = `SELECT 1 FROM UpdateCases WHERE id = ? AND user_id = ? LIMIT 1`;
  const userId = req.user.id;

  db.get(caseExistsQuery, [caseId, userId], (err, row) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Case not found or does not belong to the user' });
    }

    // If the case exists, insert the opponent details
    const insertQuery = `
      INSERT INTO OpponentDetails (case_id, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.run(insertQuery, [caseId, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId, userId], function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Failed to add opponent details' });
      }
      return res.json({ message: 'Opponent details added successfully' });
    });
  });
});

app.get('/opponent-details/:caseId', authenticateJWT, async (req, res) => {
  const { caseId } = req.params;
  const userId = req.user.id; // User ID from the JWT token

  // Validate caseId is provided
  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  // SQL query to fetch opponent details for the specified caseId and userId
  const selectQuery = `
    SELECT * FROM OpponentDetails
    WHERE case_id = ? AND user_id = ?
    ORDER BY id DESC
  `;

  db.all(selectQuery, [caseId, userId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (rows.length === 0) {
      // No opponent details found for this case ID
      return res.status(404).json({ error: 'No opponent details found for this case' });
    }
    // Return the fetched opponent details
    res.json(rows);
  });
});

app.delete('/opponent-detail/:detailId', authenticateJWT, async (req, res) => {
  const { detailId } = req.params;
  const userId = req.user.id; // User ID from the JWT token

  // SQL query to delete opponent detail for the specified detailId and userId
  const deleteQuery = `
    DELETE FROM OpponentDetails
    WHERE id = ? AND user_id = ?
  `;

  db.run(deleteQuery, [detailId, userId], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (this.changes === 0) {
      // No opponent detail was deleted, possibly because it doesn't exist or doesn't belong to the user
      return res.status(404).json({ error: 'Opponent detail not found or not authorized' });
    }
    // Successfully deleted the opponent detail
    res.json({ message: 'Opponent detail deleted successfully' });
  });
});

app.post('/concernedperson', authenticateJWT, async (req, res) => {
  const { caseId, client, team, clientDesignation, opponentPartyName, lawyerName, mobileNo, emailId, type, lawyerType } = req.body;

  if (!caseId) {
    return res.status(400).json({ error: 'Case ID is required' });
  }

  const updateQuery = `
    UPDATE UpdateCases SET
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


app.get("/edit/updatecases", authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.all(
    "SELECT id, title, cino,court, case_no,court_type, court_no_desg_name, date_last_list, date_next_list, date_of_decision, district_code, district_name, establishment_code, establishment_name, fil_no, fil_year, lcourt_no_desg_name, ldistrict_name, lestablishment_name, lpetparty_name, lresparty_name, lstate_name, ltype_name, petparty_name, note, reg_no, reg_year, resparty_name, state_code, state_name, type_name, updated, client, team, clientDesignation, opponentPartyName, lawyerName , mobileNo , emailId, type, lawyerType FROM UpdateCases WHERE user_id = ? ORDER BY id DESC",
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

    // Retrieve case data from the database
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

    // Define the HTML content with the case data embedded directly
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Update Case Data</title>
    <style>
    body {
        font-family: 'Arial', sans-serif;
        background-color: #fafafa;
        margin: 0;
        padding: 20px;
    }
    table {
        width: 100%;
        max-width: 800px;
        margin: 20px auto;
        border-collapse: collapse;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        border-radius: 8px;
        overflow: hidden;
    }
    th, td {
        padding: 15px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }
    th {
        background-color: #007bff;
        color: #ffffff;
        font-size: 16px;
    }
    td {
        color: #666;
        font-size: 14px;
    }
    tr:nth-child(even) {
        background-color: #f2f2f2;
    }
    .table-header {
        margin: 20px 0;
        font-size: 24px;
        text-align: center;
        color: #333;
    }
</style>
</head>
<body>
    <div class="table-header">Update Case Data</div>
    <table>
        <thead>
            <tr>
                <th>Field</th>
                <th>Data</th>
            </tr>
        </thead>
        <tbody>
    <tr><td>Title</td><td>${caseData.title}</td></tr>
    <tr><td>CNR NO</td><td>${caseData.cino}</td></tr>
    <tr><td>Case No</td><td>${caseData.case_no}</td></tr>
    <tr><td>Court No/Designation</td><td>${caseData.court_no_desg_name}</td></tr>
    <tr><td>Date Next Listed</td><td>${caseData.date_next_list}</td></tr>
    <tr><td>Date of Decision</td><td>${caseData.date_of_decision}</td></tr>
    <tr><td>District Code</td><td>${caseData.district_code}</td></tr>
    <tr><td>District Name</td><td>${caseData.district_name}</td></tr>
    <tr><td>Establishment Code</td><td>${caseData.establishment_code}</td></tr>
    <tr><td>Establishment Name</td><td>${caseData.establishment_name}</td></tr>
    <tr><td>Filing No</td><td>${caseData.fil_no}</td></tr>
    <tr><td>Filing Year</td><td>${caseData.fil_year}</td></tr>
    <tr><td>Petparty Name</td><td>${caseData.petparty_name}</td></tr>
    <tr><td>Note</td><td>${caseData.note}</td></tr>
    <tr><td>Registration No</td><td>${caseData.reg_no}</td></tr>
    <tr><td>Registration Year</td><td>${caseData.reg_year}</td></tr>
    <tr><td>Resparty Name</td><td>${caseData.resparty_name}</td></tr>
    <tr><td>State Code</td><td>${caseData.state_code}</td></tr>
    <tr><td>State Name</td><td>${caseData.state_name}</td></tr>
    <tr><td>Type Name</td><td>${caseData.type_name}</td></tr>
</tbody>

    </table>
</body>
</html>
    `;

    // Launch Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Set the content of the page to the HTML
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

    // Generate the PDF from the content
    const pdfBuffer = await page.pdf({
      format: 'A4',
      printBackground: true,
    });

    // Close the browser
    await browser.close();

    // Set response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=UpdateCase_${caseId}.pdf`);

    // Send the PDF buffer in the response
    res.send(pdfBuffer);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/edit/updatecases/update/:caseId', authenticateJWT, (req, res) => {
  const caseId = req.params.caseId;
  const userId = req.user.id;
  const {
    cino, court, case_no, court_no_desg_name, date_last_list, date_next_list,
    date_of_decision, district_code, district_name, establishment_code,
    establishment_name, fil_no, fil_year, lcourt_no_desg_name, ldistrict_name,
    lestablishment_name, lpetparty_name, lresparty_name, lstate_name,
    ltype_name, petparty_name, note, reg_no, reg_year, resparty_name,
    state_code, state_name, type_name, updated, client, team, clientDesignation,
    opponentPartyName, lawyerName, mobileNo, emailId, type, lawyerType
  } = req.body;

  // Update the case in the UpdateCases table
  db.run(
    'UPDATE UpdateCases SET cino = ?,court = ?, case_no = ?, court_no_desg_name = ?, date_last_list = ?, date_next_list = ?, date_of_decision = ?, district_code = ?, district_name = ?, establishment_code = ?, establishment_name = ?, fil_no = ?, fil_year = ?, lcourt_no_desg_name = ?, ldistrict_name = ?, lestablishment_name = ?, lpetparty_name = ?, lresparty_name = ?, lstate_name = ?, ltype_name = ?, petparty_name = ?, note = ?, reg_no = ?, reg_year = ?, resparty_name = ?, state_code = ?, state_name = ?, type_name = ?, updated = ?, client = ?, team = ?, clientDesignation = ?, opponentPartyName = ?, lawyerName = ? , mobileNo = ? , emailId = ?, type = ?, lawyerType = ?  WHERE id = ? AND user_id = ?',
    [cino, case_no, court_no_desg_name, date_last_list, date_next_list, date_of_decision, district_code, district_name, establishment_code, establishment_name, fil_no, fil_year, lcourt_no_desg_name, ldistrict_name, lestablishment_name, lpetparty_name, lresparty_name, lstate_name, ltype_name, petparty_name, note, reg_no, reg_year, resparty_name, state_code, state_name, type_name, updated, client, team, clientDesignation,
      opponentPartyName, lawyerName, mobileNo, emailId, type, lawyerType, caseId, userId],
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
    'SELECT id, firstName, lastName, email, mobileNo, alternateMobileNo, organizationName, organizationType, organizationWebsite, caseTitle, type, homeAddress, officeAddress, assignAlerts, assignAppointments FROM ClientForm WHERE user_id = ? ORDER BY id DESC',
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
    db.all('SELECT id,firstName,lastName,email,mobileNo,assignAlerts,assignAppointments FROM ClientForm WHERE user_id = ? ORDER BY id DESC', [userId], (err, forms) => {
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

    // Retrieve client data from the database
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

    // Define the HTML content for the PDF
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Data</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f0f8ff;
            margin: 0;
            padding: 20px;
        }
        table {
            width: 100%;
            max-width: 800px;
            margin: 20px auto;
            border-collapse: collapse;
        }
        th, td {
            text-align: left;
            padding: 8px;
            font-size: 16px;
            border: 1px solid #ddd;
        }
        th {
            background-color: #007bff;
            color: #ffffff;
        }
        td {
            background-color: #e7f3fe;
        }
        tr:nth-child(even) td {
            background-color: #d1e7fd;
        }
        .table-header {
            background-color: #0056b3;
            color: #ffffff;
            padding: 10px;
            font-size: 20px;
            text-align: center;
            margin-bottom: 10px;
            border-radius: 4px;
        }
    </style>
</head>
<body>

<div class="table-header">Client Data</div>
<table>
    <thead>
        <tr>
            <th>Field</th>
            <th>Information</th>
        </tr>
    </thead>
    <tbody>
    <tr><td>First Name</td><td>${clientData.firstName}</td></tr>
    <tr><td>Last Name</td><td>${clientData.lastName}</td></tr>
    <tr><td>Email</td><td>${clientData.email}</td></tr>
    <tr><td>Mobile No</td><td>${clientData.mobileNo}</td></tr>
    <tr><td>Alternate Mobile No</td><td>${clientData.alternateMobileNo}</td></tr>
    <tr><td>Organization Name</td><td>${clientData.organizationName}</td></tr>
    <tr><td>Organization Type</td><td>${clientData.organizationType}</td></tr>
    <tr><td>Organization Website</td><td>${clientData.organizationWebsite}</td></tr>
    <tr><td>Case</td><td>${clientData.caseTitle}</td></tr>
    <tr><td>Type</td><td>${clientData.type}</td></tr>
    <tr><td>Home Address</td><td>${clientData.homeAddress}</td></tr>
    <tr><td>Office Address</td><td>${clientData.officeAddress}</td></tr>
    <tr><td>Assign Alerts</td><td>${clientData.assignAlerts}</td></tr>
    <tr><td>Assign Appointments</td><td>${clientData.assignAppointments}</td></tr>
</tbody>

</table>

</body>
</html>
`;

    // Launch Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Set the content of the page to the HTML
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

    // Generate the PDF from the page content
    const pdfBuffer = await page.pdf({
      format: 'A4',
      printBackground: true,
    });

    // Close the browser
    await browser.close();

    // Set the response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Client_${clientId}.pdf`);

    // Send the PDF buffer in the response
    res.send(pdfBuffer);
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

app.get('/api/subscription-status', authenticateJWT, (req, res) => {
  const userId = req.user.id;

  db.get( // Using db.get since we expect a single row result.
    'SELECT trial_start_date, subscription_end_date FROM users WHERE id = ?',
    [userId],
    (err, user) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Normalize today's date to start of day for comparison
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      let isAccessAllowed = false;

      let trialEndDate = user.trial_start_date ? new Date(user.trial_start_date) : null;
      if (trialEndDate) {
        trialEndDate.setDate(trialEndDate.getDate() + 15);
        trialEndDate.setHours(0, 0, 0, 0); // Normalize trial end date
        if (today <= trialEndDate) {
          isAccessAllowed = true;
        }
      }

      let subscriptionEndDate = user.subscription_end_date ? new Date(user.subscription_end_date) : null;
      if (subscriptionEndDate) {
        subscriptionEndDate.setHours(0, 0, 0, 0); // Normalize subscription end date
        if (today <= subscriptionEndDate) {
          isAccessAllowed = true;
        }
      }

      return res.json({ isAccessAllowed });
    }
  );
});




// POST endpoint to add a new CNR form
app.post('/cnr', authenticateJWT, checkAccess, async (req, res) => {
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
    'SELECT id, invoiceNumber, client, caseType, date, amount, taxType, taxPercentage, fullAddress, hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType, expensesTaxPercentage, expensesCumulativeAmount,totalAmount,CumulativeAmount, addDoc FROM InvoicesForm WHERE user_id = ? ORDER BY id DESC',
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
    invoiceNumber, CumulativeAmount, client, caseType, date, amount, taxType, taxPercentage, fullAddress,
    hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType, expensesTaxPercentage, expensesCumulativeAmount, totalAmount, addDoc
  } = req.body;

  db.run(
    'UPDATE InvoicesForm SET invoiceNumber = ?,CumulativeAmount = ?, client = ?, caseType = ?, date = ?, amount = ?, taxType = ?, taxPercentage = ?, fullAddress = ?, hearingDate = ?, title = ?, dateFrom = ?, dateTo = ?, expensesAmount = ?, expensesTaxType = ?, expensesTaxPercentage = ?, expensesCumulativeAmount = ?,totalAmount = ?, addDoc = ? WHERE id = ? AND user_id = ?',
    [invoiceNumber, CumulativeAmount, client, caseType, date, amount, taxType, taxPercentage, fullAddress, hearingDate, title, dateFrom, dateTo, expensesAmount, expensesTaxType, expensesTaxPercentage, expensesCumulativeAmount, totalAmount, addDoc, invoiceId, userId],
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
    ], function (err) {
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

    // Retrieve invoice data from the database
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

    // Define the HTML content for the PDF
    // Replace 'ejs.render' with template literals
    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Invoice Data</title>
    <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f9f9f9;
                color: #333;
            }
            .container {
                max-width: 800px;
                margin: 40px auto;
                padding: 20px;
                background-color: #fff;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .header {
                text-align: center;
                margin-bottom: 20px;
            }
            .header h1 {
                color: #444;
                margin: 0;
                padding: 0;
            }
            .taglines {
                font-style: italic;
                color: #888;
                margin-bottom: 40px;
            }
            .invoice-header {
                font-weight: bold;
                color: #333;
                border-bottom: 2px solid #ddd;
                padding-bottom: 10px;
                margin-bottom: 20px;
            }
            .invoice-data table {
                width: 100%;
                border-collapse: collapse;
            }
            .invoice-data th,
            .invoice-data td {
                text-align: left;
                padding: 8px;
            }
            .invoice-data th {
                background-color: #f2f2f2;
            }
            .invoice-data td {
                border-bottom: 1px solid #ddd;
            }
            .total {
                text-align: right;
                margin-top: 20px;
                font-size: 18px;
                font-weight: bold;
            }
        </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>LAWFAX</h1>
            <span class="taglines">WHERE FACTS MEET THE LAW</span>
        </div>

        <div class="invoice-data">
            <h2 class="invoice-header">Invoice</h2>
            <table>
            <tr><th>Title:</th><td>${invoiceData.title}</td></tr>
            <tr><th>Invoice Number:</th><td>${invoiceData.invoiceNumber}</td></tr>
            <tr><th>Date:</th><td>${invoiceData.date}</td></tr>
            <tr><th>Client:</th><td>${invoiceData.client}</td></tr>
            <tr><th>Case Type:</th><td>${invoiceData.caseType}</td></tr>
            <tr><th>Amount:</th><td>$${invoiceData.amount}</td></tr>
            <tr><th>Tax Type:</th><td>${invoiceData.taxType}</td></tr>
            <tr><th>Tax Percentage:</th><td>${invoiceData.taxPercentage}%</td></tr>
            <tr><th>Cumulative Amount:</th><td>$${invoiceData.CumulativeAmount}</td></tr>
            <tr><th>Full Address:</th><td>${invoiceData.fullAddress}</td></tr>
            <tr><th>Date From:</th><td>${invoiceData.dateFrom}</td></tr>
            <tr><th>Date To:</th><td>${invoiceData.dateTo}</td></tr>
            <tr><th>Expenses Amount:</th><td>$${invoiceData.expensesAmount}</td></tr>
            <tr><th>Expenses Tax Type:</th><td>${invoiceData.expensesTaxType}</td></tr>
            <tr><th>Expenses Tax Percentage:</th><td>${invoiceData.expensesTaxPercentage}%</td></tr>
            <tr><th>Expenses Cumulative Amount:</th><td>$${invoiceData.expensesCumulativeAmount}</td></tr>
            <!-- Include other invoice fields similarly -->
        </table>
        <div class="total">
            Total Amount with all Expenses: $${invoiceData.totalAmount}
        </div>
        </div>
    </div>
</body>
</html>
`;

    // Launch Puppeteer
    const browser = await puppeteer.launch();
    const page = await browser.newPage();

    // Set the content of the page to the HTML
    await page.setContent(htmlContent, { waitUntil: 'networkidle0' });

    // Generate the PDF from the page content
    const pdfBuffer = await page.pdf({
      format: 'A4',
      printBackground: true,
    });

    // Close the browser
    await browser.close();

    // Set the response headers for PDF download
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Invoice_${invoiceId}.pdf`);

    // Send the PDF buffer in the response
    res.send(pdfBuffer);
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
    db.all('SELECT id, title, type_name, court_type, state_name, district_name, date_next_list FROM UpdateCases WHERE user_id = ?', [userId], (err, cases) => {
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
app.post('/partyname', authenticateJWT, checkAccess, async (req, res) => {
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
app.post('/updateEmailNoti', authenticateJWT, checkAccess, async (req, res) => {
  const userId = req.user.id; // Assuming `authenticateJWT` middleware adds `user` to `req`
  const { emailNoti } = req.body; // Expected to be 1 or 0

  // Update the `emailNoti` field in the `users` table for the authenticated user
  const query = `UPDATE users SET emailNoti = ? WHERE id = ?`;
  db.run(query, [emailNoti, userId], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: 'Notification settings updated successfully' });
  });
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
app.get('/dashboard/user/notifications', authenticateJWT, checkAccess, (req, res) => {
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

app.get('/dashboard/user/notifications/count', authenticateJWT, checkAccess, (req, res) => {
  const userId = req.user.id;

  db.get(`SELECT COUNT(*) AS count FROM Notification WHERE user_id = ? AND isViewed = 0`, [userId], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    res.json({ count: row.count });
  });
});

app.delete('/dashboard/user/notifications/:notificationId', authenticateJWT, checkAccess, async (req, res) => {
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
// Assuming you're using the sqlite3 library and have a db object
const getCaseIdByTitle = async (caseTitle) => {
  console.log("Looking up ID for caseTitle:", caseTitle);
  return new Promise((resolve, reject) => {
    db.get("SELECT id FROM UpdateCases WHERE title = ?", [caseTitle], (err, row) => {
      if (err) {
        console.error("Database error in getCaseIdByTitle:", err);
        reject(err);
      } else {
        console.log("Found caseId:", row ? row.id : "No matching case found");
        resolve(row ? row.id : null);
      }
    });
  });
};


// Promisified run method
const runAsync = (sql, params) => new Promise((resolve, reject) => {
  db.run(sql, params, function (err) {
    if (err) reject(err);
    else resolve(this);
  });
});

// notifications for proxy
app.post('/proxy', authenticateJWT, upload.single('caseFile'), checkAccess, async (req, res) => {
  console.log("Request body:", req.body);

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
    comments,
   
  } = req.body;

  const caseId = Array.isArray(req.body.caseId) ? req.body.caseId[0] : req.body.caseId;
  console.log("Received caseId:", caseId);

  const caseFilePath = req.file ? req.file.filename : null;
  const fileUrl = caseFilePath ? `${req.protocol}://${req.get('host')}/uploads/${caseFilePath}` : null;
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
      expirationDate,
      caseFile,
      caseId
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? , ?)`;
    console.log("Inserting with caseId:", caseId);

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
      expirationDate,
      caseFilePath,
      caseId,
    ]);
    console.log("Received caseId:", caseId);
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
    const notificationMessage = `A new proxy has been generated by ${createdByUser}. Need a ${lawyerType}  having ${experience} of experience and Enrollment Year around ${courtNumber}.The Court Hearing is on ${dateOfHearing} in ${city}, ${zipStateProvince}.Case fee is ₹ ${age} only.` + (fileUrl ? ` <a  class="anchortag" href="${fileUrl}">click here to see case file</a>` : '');

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

app.get('/dashboard/user/proxy-notifications', authenticateJWT, checkAccess, (req, res) => {
  const userId = req.user.id;

  // Adjusted query to exclude finalized proxies
  const query = `
    SELECT n.id, n.message, n.expirationDate, n.proxy_id, pf.age
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
      proxyId: row.proxy_id,
      amount: row.age
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
    const notificationMessage = `${user.name} has accepted your proxy for hearing date ${proxy.dateOfHearing}.He is a ${user.lawyerType} ,having Enrollment No-${user.age} and ${user.experience} years of experience. You can contact me through email-${user.username} or by mobile-${user.mobile} `;

    // Insert the notification for the proxy creator
    await runAsync('INSERT INTO Notification (user_id, message, expirationDate, type, proxy_id, acceptorId) VALUES (?, ?, ?, ?, ?, ?)', [proxy.user_id, notificationMessage, proxy.expirationDate, 'proxy-accepted', proxy.id, userId]);

    res.status(201).json({ message: 'Proxy accepted successfully', notificationMessage });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Internal Server Error', details: error.message });
  }
});


app.get('/dashboard/user/proxy-notifications-accepted', authenticateJWT, checkAccess, (req, res) => {
  const userId = req.user.id; // Extracting user ID from JWT authentication

  db.all(`
    SELECT 
      n.id AS notificationId, 
      n.message, 
      n.expirationDate, 
      n.proxy_id AS proxyId, 
      n.acceptorId,
      pf.age AS amount
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

    res.json(rows.map(row => ({
      ...row,
      amount: row.amount // Ensure amount is correctly mapped in the response
    })));
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
    await runAsync('INSERT INTO Notification (user_id, message, expirationDate, proxy_id) VALUES (?, ?, ?, ?)', [acceptorId, notificationMessageForAcceptor, proxy.expirationDate, proxy.id]);

    res.json({ message: 'Acceptor chosen successfully, notifications sent.' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// show proxy
// Endpoint for retrieving proxy activity for the logged-in user
app.get('/dashboard/user/proxy-activity', authenticateJWT, checkAccess, (req, res) => {
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
     WHERE pa.creator_user_id = ? AND p.expirationDate > ?
     ORDER BY pa.id DESC`,

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
app.delete('/dashboard/user/proxy-activity/:activityId', authenticateJWT, checkAccess, (req, res) => {
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
  db.get('SELECT COUNT(*) as count FROM UpdateCases WHERE user_id = ?', [userId], (err, result) => {
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
  console.log("yoyohoney", userId)
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

    const newAvatarUrl = `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random&color=fff`;
    updateFields.push('avatar_url = ?');
    updateValues.push(newAvatarUrl);
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
