// const sqlite3 = require('sqlite3').verbose();

// let db = new sqlite3.Database('./Data_base/judgments5.db', sqlite3.OPEN_READWRITE, (err) => {
//   if (err) {
//     console.error(err.message);
//     throw err;
//   }
//   console.log('Connected to the SQLite database.');
// });

// const getUserByUsername = (username) => {
//   return new Promise((resolve, reject) => {
//     db.get('SELECT id, username, hashed_password FROM users WHERE username = ?', [username], (err, user) => {
//       if (err) {
//         reject(err);
//       } else {
//         resolve(user);
//       }
//     });
//   });
// };

// const createUser = (username, hashedPassword) => {
//   return new Promise((resolve, reject) => {
//     db.run('INSERT INTO users (username, hashed_password) VALUES (?, ?)', [username, hashedPassword], function(err) {
//       if (err) {
//         reject(err);
//       } else {
//         resolve({ id: this.lastID, username });
//       }
//     });
//   });
// };

// module.exports = { getUserByUsername, createUser };
