const bcrypt = require('bcryptjs');

const password = "adminPassword"; // Replace "adminPassword" with the actual password you want to hash  //LawfaxNupur@123
bcrypt.hash(password, 10, function(err, hashedPassword) {
  if (err) {
    return console.error(err);
  }
  console.log("Hashed Password:", hashedPassword);
});
