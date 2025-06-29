const bcrypt = require('bcrypt');

const newPassword = 'vasudev';  // Set the new password you want for the admin
const saltRounds = 10;

bcrypt.hash(newPassword, saltRounds, (err, hash) => {
    if (err) {
        console.error("Error hashing password:", err);
    } else {
        console.log("New Hashed Password:", hash);
    }
<<<<<<< HEAD
});
=======
});
>>>>>>> 3d3eaa666bc79b072af73f5d3ffa91ebbfdcd0e1
