const express = require('express');
const mysql = require('mysql2/promise'); // promise를 사용하는 mysql2 모듈을 가져옴
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/login', (req, res) => {
    res.render("login");
});
// 화면 엔진은 ejs로 설정한다.
app.set("view engine", "ejs");

// 정적 파일 경로 설정
app.use('/public', express.static('public'));

// Express에서 정적파일 제공
app.use('/static', express.static('static'));

// 세션 설정
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: false
}));

// MySQL 연결
require('dotenv').config();

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// 로그인
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('Username:', username, 'Password:', password); // 로그 추가
  
    try {
        const [results] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
      
        if (results.length === 0) {
            res.status(401).send('Incorrect username or password');
            return;
        }
      
        console.log('Retrieved hash:', results[0].password); // 로그 추가
        const isMatch = await bcrypt.compare(password, results[0].password);
      
        if (!isMatch) {
            res.status(401).send('Incorrect username or password');
            return;
        }
      
        req.session.userId = results[0].id;
        res.send(`Logged in successfully. Hello ${username}!`);
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('Login failed');
    }
});

// 로그아웃
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            res.status(500).send('Logout failed');
            return;
        }
        res.send('Logged out successfully');
    });
});

// 대시보드 페이지
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.send('Welcome to your dashboard!');
});

// 인증 미들웨어
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.status(401).send('You need to log in');
}

// 회원가입 페이지
app.get('/register', (req, res) => {
    res.send(`
      <h1>Register</h1>
      <form action="/register" method="POST">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <button type="submit">Register</button>
      </form>
    `);
});

// 회원가입 처리
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
        await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        res.send(`Registration successful ${username}. <a href="/">Go to login</a>`);
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(409).send('Username already exists. Please choose another.');
        } else {
            console.error('Error during registration:', err);
            res.status(500).send('Registration failed');
        }
    }
});

// 서버 시작
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
