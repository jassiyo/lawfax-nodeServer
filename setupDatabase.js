const sqlite3 = require('sqlite3').verbose();

let db = new sqlite3.Database('./Data_base/New-db/judgments5.db', (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log('Connected to the SQLite database.');
});

db.serialize(() => {
  db.run('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, category TEXT)', (err) => {
    if (err) {
      // Table already created
    } else {
      // Table just created, creating some rows
      const insert = 'INSERT INTO items (name, category) VALUES (?,?)';
      db.run(insert, ["Item1","Advocate"]);
      db.run(insert, ["Item2","Judge"]);
      db.run(insert, ["Item3","case_no"]);
    }
  });  
});

db.close();
