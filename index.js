const express = require('express');
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const app = express();
const port = process.env.PORT || 3000;

// MongoDB Connection
mongoose.connect('mongodb://localhost/student-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

// Define the Student schema
const studentSchema = new mongoose.Schema({
  name: String,
  age: Number,
  email: String,
});

const Student = mongoose.model('Student', studentSchema);

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60 * 60 * 1000 }, // Session expires in 1 hour
  })
);

// Set up EJS as the template engine
app.set('view engine', 'ejs');

// JWT Secret Key
const jwtSecret = 'your-jwt-secret';

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

// User registration
app.post(
  '/register',
  [
    body('name').notEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }).trim(),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    const student = new Student({
      name,
      email,
      password: hashedPassword,
    });

    student.save((err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error saving student.');
      }
      res.status(201).json({ message: 'Student registered successfully!' });
    });
  }
);

// User login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check if the user exists in the database
  const student = await Student.findOne({ email });

  if (!student) {
    return res.status(401).json({ message: 'Authentication failed' });
  }

  // Compare the provided password with the hashed password
  const passwordMatch = await bcrypt.compare(password, student.password);

  if (!passwordMatch) {
    return res.status(401).json({ message: 'Authentication failed' });
  }

  // Generate a JWT token
  const token = jwt.sign({ email: student.email }, jwtSecret, {
    expiresIn: '1h', // Token expires in 1 hour
  });

  // Store the token in a cookie
  res.cookie('jwt', token, { httpOnly: true, maxAge: 3600000 }); // 1 hour

  res.json({ message: 'Login successful', token });
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.cookies.jwt;

  if (!token) {
    return res.status(401).json({ message: 'Authentication failed' });
  }

  jwt.verify(token, jwtSecret, (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    req.user = decodedToken;
    next();
  });
};

// CRUD operations for students
app.get('/students', verifyToken, async (req, res) => {
  const students = await Student.find();
  res.render('students', { students });
});

app.get('/students/add', verifyToken, (req, res) => {
  res.render('add-student');
});

app.post(
  '/students/add',
  verifyToken,
  [
    body('name').notEmpty().trim().escape(),
    body('age').isInt(),
    body('email').isEmail().normalizeEmail(),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, age, email } = req.body;

    const student = new Student({
      name,
      age,
      email,
    });

    student.save((err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error adding student.');
      }
      res.status(201).redirect('/students');
    });
  }
);

app.get('/students/edit/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const student = await Student.findById(id);
  res.render('edit-student', { student });
});

app.post(
  '/students/edit/:id',
  verifyToken,
  [
    body('name').notEmpty().trim().escape(),
    body('age').isInt(),
    body('email').isEmail().normalizeEmail(),
  ],
  async (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const id = req.params.id;
    const { name, age, email } = req.body;

    const student = await Student.findById(id);

    if (!student) {
      return res.status(404).json({ message: 'Student not found' });
    }

    student.name = name;
    student.age = age;
    student.email = email;

    student.save((err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Error updating student.');
      }
      res.status(200).redirect('/students');
    });
  }
);

app.get('/students/delete/:id', verifyToken, async (req, res) => {
  const id = req.params.id;

  const student = await Student.findById(id);

  if (!student) {
    return res.status(404).json({ message: 'Student not found' });
  }

  student.remove((err) => {
    if (err) {
      console.error(err);
      return res.status(500).send('Error deleting student.');
    }
    res.status(200).redirect('/students');
  });
});

// Logout route
app.get('/logout', (req, res) => {
  res.clearCookie('jwt');
  res.redirect('/');
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
