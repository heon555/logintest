// 필요한 모듈을 가져옵니다.
const express = require('express');
const mysql = require('mysql2/promise'); // promise를 사용하는 mysql2 모듈
const bcrypt = require('bcrypt'); // 비밀번호 해시를 위한 bcrypt 모듈
const session = require('express-session'); // 사용자 세션 관리를 위한 express-session 모듈
require('dotenv').config(); // .env 파일에서 환경 변수를 불러옵니다.

//파일 업로드 기능을 위한 미들웨어
const multer = require('multer'); // multer 모듈 추가
const path = require('path');

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

// Multer 파일 업로드 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // 파일 저장 경로
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // 파일 이름 설정
  }
});
const upload = multer({ storage: storage }); // multer 설정 완료

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
      
        if (results.length === 0) {
            res.status(401).send('Incorrect username or password');
            return;
        }
      
        console.log('Retrieved hash:', results[0].password); // 해시된 비밀번호 디버그 로그
        const isMatch = await bcrypt.compare(password, results[0].password);
      
        if (!isMatch) {
            res.status(401).send('Incorrect username or password');
            return;
        }
      
        // 로그인 성공 시 세션에 사용자 ID 저장
        req.session.userId = results[0].id;
        res.redirect('/'); //로그인 성공 시 메인 페이지 리디렉션
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).send('Login failed');
    }
});

// 홈페이지를 위한 GET 라우트
app.get('/', async (req, res) => {
    try {
        const [articles] = await db.query('SELECT id, title, created_at FROM articles ORDER BY created_at DESC');
        res.render('index', { articles });
    } catch (err) {
        console.error('Error fetching articles:', err);
        res.status(500).send('Failed to load articles');
    }
});

// 인증 확인 미들웨어
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.status(401).send('You need to log in');
}

// 회원가입 페이지를 위한 GET 라우트
app.get('/register', (req, res) => {
    res.render('register');
});

// 회원가입 요청 처리를 위한 POST 라우트
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
  
    try {
        await db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        res.render('registration_success', {username});
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            res.status(409).render('already_exists');
        } else {
            console.error('Error during registration:', err);
            res.status(500).render('registration_failed');
        }
    }
});

// 서버를 시작하고 설정된 포트에서 요청을 수신합니다.
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

// 게시글 작성 폼을 렌더링하는 GET 라우트 (로그인 확인)
app.get('/articles/new', isAuthenticated, (req, res) => {
    res.render('new_article');
});

// 게시글 작성 요청을 처리하는 POST 라우트
app.post('/articles', isAuthenticated, upload.single('attachment'), async (req, res) => {
    const { title, content, category } = req.body; // category
    const authorId = req.session.userId;
    const filePath = req.file ? req.file.path : null;

    try {
        await db.query(
            'INSERT INTO articles (title, content, author_id, category, attachment) VALUES (?, ?, ?, ?, ?)',
            [title, content, authorId, category, filePath] // category
        );
        res.redirect('/');
    } catch (err) {
        console.error('Error during article creation:', err);
        res.status(500).send('Failed to create article');
    }
});


// 게시글 수정 폼을 렌더링하는 GET 라우트
app.get('/articles/:id/edit', isAuthenticated, async (req, res) => {
    const articleId = req.params.id;
    try {
        const [results] = await db.query('SELECT * FROM articles WHERE id = ? AND author_id = ?', [articleId, req.session.userId]);
        if (results.length === 0) {
            return res.status(403).send('Unauthorized to edit this article');
        }
        res.render('edit_article', { article: results[0] });
    } catch (err) {
        console.error('Error during article edit fetch:', err);
        res.status(500).send('Failed to retrieve article');
    }
});

// 게시글 수정을 처리하는 POST 라우트
app.post('/articles/:id/edit', isAuthenticated, async (req, res) => {
    const articleId = req.params.id;
    const { title, content } = req.body;
    try {
        const [result] = await db.query('UPDATE articles SET title = ?, content = ? WHERE id = ? AND author_id = ?', [title, content, articleId, req.session.userId]);
        if (result.affectedRows === 0) {
            return res.status(403).send('Unauthorized to edit this article');
        }
        res.redirect(`/articles/${articleId}`);
    } catch (err) {
        console.error('Error during article update:', err);
        res.status(500).send('Failed to update article');
    }
});

//게시글 삭제를 처리하는 POST 라우트
app.post('/articles/:id/delete', isAuthenticated, async (req, res) => {
    const articleId = req.params.id;
    try {
        const [result] = await db.query('DELETE FROM articles WHERE id = ? AND author_id = ?', [articleId, req.session.userId]);
        if (result.affectedRows === 0) {
            return res.status(403).send('Unauthorized to delete this article');
        }
        res.redirect('/');
    } catch (err) {
        console.error('Error during article deletion:', err);
        res.status(500).send('Failed to delete article');
    }
});


// 개별 게시글을 보여주는 GET 라우트
app.get('/articles/:id', async (req, res) => {
    const articleId = req.params.id;
    try {
        const [results] = await db.query(`
            SELECT articles.*, users.username AS author_name 
            FROM articles 
            JOIN users ON articles.author_id = users.id 
            WHERE articles.id = ?`, 
            [articleId]);
        if (results.length === 0) {
            return res.status(404).send('Article not found');
        }
        // session.userId를 함께 전달
        res.render('view_article', { article: results[0], userId: req.session.userId });
    } catch (err) {
        console.error('Error fetching article:', err);
        res.status(500).send('Failed to load article');
    }
});


app.get('/articles/category/:category', async (req, res) => {
    const category = req.params.category;
    try {
        const [articles] = await db.query('SELECT * FROM articles WHERE category = ? ORDER BY created_at DESC', [category]);
        res.render('category_articles', { articles, category });
    } catch (err) {
        console.error('Error fetching articles by category:', err);
        res.status(500).send('Failed to load articles by category');
    }
});
