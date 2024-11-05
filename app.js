// 필요한 모듈을 가져옵니다.
const express = require('express');
const mysql = require('mysql2/promise'); // promise를 사용하는 mysql2 모듈
const bcrypt = require('bcrypt'); // 비밀번호 해시를 위한 bcrypt 모듈
const session = require('express-session'); // 사용자 세션 관리를 위한 express-session 모듈
require('dotenv').config(); // .env 파일에서 환경 변수를 불러옵니다.

// Express 애플리케이션을 초기화합니다.
const app = express();

// 서버 포트 설정
const PORT = 3000;

// JSON 및 URL-encoded 데이터 파싱 미들웨어를 추가합니다.
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 화면 엔진을 EJS로 설정하여 템플릿을 렌더링합니다.
app.set("view engine", "ejs");

// 정적 파일 경로 설정
app.use('/public', express.static('public'));
app.use('/static', express.static('static'));

// 세션 미들웨어 설정
app.use(session({
  secret: 'your_secret_key', // 실제 배포 시에는 강력한 비밀 키로 교체하세요.
  resave: false,
  saveUninitialized: false
}));

// MySQL 연결 풀 생성
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// 로그인 페이지를 위한 GET 라우트
app.get('/login', (req, res) => {
    res.render("login"); // 로그인 화면 렌더링
});

// 로그인 요청 처리를 위한 POST 라우트
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('Username:', username, 'Password:', password); // 디버그용 로그 추가
  
    try {
        // 데이터베이스에서 사용자 정보를 조회
        const [results] = await db.query('SELECT * FROM users WHERE username = ?', [username]);
      
        // 사용자가 없을 경우, 인증 실패 상태를 전송
        if (results.length === 0) {
            res.status(401).send('Incorrect username or password');
            return;
        }
      
        console.log('Retrieved hash:', results[0].password); // 해시된 비밀번호 디버그 로그
        const isMatch = await bcrypt.compare(password, results[0].password); // 비밀번호 해시 비교
      
        if (!isMatch) {
            res.status(401).send('Incorrect username or password');
            return;
        }
      
        // 로그인 성공 시 세션에 사용자 ID 저장
        req.session.userId = results[0].id;
        res.render("login_success", {username});
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('Login failed'); // 서버 오류 발생 시 응답 전송
    }
});

// 홈페이지를 위한 GET 라우트
app.get('/', (req, res) => {
    res.render('index'); // 메인 페이지 렌더링
});

// 인증 확인 미들웨어
function isAuthenticated(req, res, next) {
    if (req.session.userId) { // 세션에 사용자 ID가 있는지 확인
        return next(); // 인증된 경우 다음으로 진행
    }
    res.status(401).send('You need to log in'); // 인증되지 않은 경우 응답 전송
}

// 회원가입 페이지를 위한 GET 라우트
app.get('/register', (req, res) => {
    res.render('register'); // 회원가입 폼 렌더링
});

// 회원가입 요청 처리를 위한 POST 라우트
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // 비밀번호를 안전하게 해싱
  
    try {
        // 새 사용자를 데이터베이스에 삽입
        await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        res.render('registration_success', {username}); // 회원가입 성공 화면 렌더링
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') { // 중복 사용자명 처리
            res.status(409).render('already_exists'); // 이미 존재하는 사용자 화면 렌더링
        } else {
            console.error('Error during registration:', err);
            res.status(500).render('registration_failed'); // 일반 오류 화면 렌더링
        }
    }
});

// 서버를 시작하고 설정된 포트에서 요청을 수신합니다.
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
