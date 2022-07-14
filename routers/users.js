const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('../middleware/auth');

//create table is not already
router.get('/createuserstable', (req, res) => {
  let sql =
    'CREATE TABLE users(id int AUTO_INCREMENT, admin BOOLEAN not null default false, name VARCHAR(255), passwordHash VARCHAR(255), PRIMARY KEY (id))';
  db.query(sql, (err, result) => {
    if (err) {
      console.log(err);
      res.send('Table already created');
    } else {
      console.log(result);
      res.send('Users table created');
    }
  });
});

//get customer (user) details
router.get('/find/:id', (req, res) => {
  const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(sql, (err, result) => {
    if (err) {
      return res.json({ message: err });
    } else {
      res.send(result);
    }
  });
});

// register user
router.post('/register', (req, res) => {
  const newUserData = {
    admin: req.body.admin,
    name: req.body.name,
    passwordHash: bcrypt.hashSync(req.body.password, 10),
  };

  // check is email already registered
  const findQuery = `SELECT * FROM users WHERE name = "${req.body.name}"`;
  const existingUser = db.query(findQuery, (err, result) => {
    if (err) {
      return res.json({ message: err });
    }
    if (result.length > 0) {
      return res.status(400).send('User already exists');
    }

    //if no user found, register new user
    const createNewUser = 'INSERT INTO users set ?';
    db.query(createNewUser, newUserData, (err, result) => {
      if (err) {
        console.log(err);
      } else {
        const token = jwt.sign(
          {
            id: result.insertId,
            admin: 0,
            name: newUserData.name,
          },
          process.env.SECRET,
          {
            expiresIn: '1d', //one day is "1d" /"1w"...
          }
        );

        //set cookie
        res
          .cookie('token', token, {
            httpOnly: true,
            sameSite:
              process.env.NODE_ENV === 'development'
                ? 'lax'
                : process.env.NODE_ENV === 'production' && 'none',
            secure:
              process.env.NODE_ENV === 'development'
                ? false
                : process.env.NODE_ENV === 'production' && true,
          })
          .status(200)
          .send({
            id: result.insertId,
            admin: 0,
            name: newUserData.name,
            token: token,
          });
      }
    });
  });
});

//login
router.post('/login', (req, res) => {
  const findQuery = `SELECT * FROM users WHERE name = "${req.body.name}"`;

  const findUser = db.query(findQuery, (err, result) => {
    if (err) {
      return res.send('No user found!');
    }
    if (result.length > 0) {
      if (bcrypt.compareSync(req.body.password, result[0].passwordHash)) {
        const token = jwt.sign(
          {
            id: result[0].id,
            admin: result[0].admin,
            name: result[0].name,
          },
          process.env.SECRET,
          {
            expiresIn: '1d', //one day is "1d" /"1w"...
          }
        );
        res
          .cookie('token', token, {
            httpOnly: true,
            sameSite:
              process.env.NODE_ENV === 'development'
                ? 'lax'
                : process.env.NODE_ENV === 'production' && 'none',
            secure:
              process.env.NODE_ENV === 'development'
                ? false
                : process.env.NODE_ENV === 'production' && true,
          })
          .status(200)
          .send({
            id: result[0].id,
            admin: result[0].admin,
            name: result[0].name,
            token: token,
          });
      } else {
        res.status(400).send('Password is wrong');
      }
    } else {
      return res.status(400).send('User not found');
    }
  });
});

// Update user profile
router.put('/update/:id', (req, res) => {
  const newData = {
    name: req.body.name,
  };

  const sql = `UPDATE users SET name = '${newData.name}', surname = '${newData.surname}', address = '${newData.address}' WHERE id = ${req.params.id}`;
  db.query(sql, (err, result) => {
    if (err) {
      return res.json({ message: err });
    } else {
      return res.json({ message: result });
    }
  });
});

// update user email
// router.put('/update/email/:id', (req, res) => {
//   const newData = {
//     email: req.body.email,
//   };

//   const sql = `UPDATE users SET email = '${newData.email}' WHERE id = ${req.params.id}`;
//   db.query(sql, (err, result) => {
//     if (err) {
//       return res.json({ message: err });
//     } else {
//       return res.json({ message: result });
//     }
//   });
// });

// update user password
router.put('/update/password/:id', (req, res) => {
  const newData = {
    name: req.body.name,
    password: req.body.password,
    passwordHash: bcrypt.hashSync(req.body.newPassword, 10),
  };

  // check user and current password
  const findQuery = `SELECT * FROM users WHERE name = "${newData.name}"`;

  const findUser = db.query(findQuery, (err, result) => {
    if (err) {
      return res.send('No user found!');
    }

    // if user
    if (result.length > 0) {
      // if old password is correct
      if (bcrypt.compareSync(req.body.password, result[0].passwordHash)) {
        // update password
        const sql = `UPDATE users SET passwordHash = '${newData.passwordHash}' WHERE id = ${req.params.id}`;
        db.query(sql, (err, result) => {
          if (err) {
            return res.json({ message: err });
          } else {
            return res.json({ message: result });
          }
        });
      } else {
        res.status(400).send('Password is wrong');
      }
    } else {
      return res.status(400).send('User not found');
    }
  });
});

//check if the user is loged in
router.get('/loggedIn', (req, res) => {
  try {
    const token = req.cookies.token;

    if (!token) return res.json(null);

    const validatedUser = jwt.verify(token, process.env.SECRET);
    res.send(validatedUser);
  } catch (err) {
    return res.json(null);
  }
});

//log out
router.post('/logout', (req, res) => {
  try {
    res
      .cookie('token', '', {
        httpOnly: true,
        sameSite:
          process.env.NODE_ENV === 'development'
            ? 'lax'
            : process.env.NODE_ENV === 'production' && 'none',
        secure:
          process.env.NODE_ENV === 'development'
            ? false
            : process.env.NODE_ENV === 'production' && true,
        expires: new Date(0),
      })
      .send('Logged out!');
  } catch (err) {
    return res.send(err);
  }
});

module.exports = router;
