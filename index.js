const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
require('dotenv').config();
const helmet = require('helmet');
const logger = require('./logger');

const app = express();
app.use(bodyParser.json());
app.use(express.json());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

// Helmet 미들웨어 추가
app.use(helmet());

// 요청 로깅 미들웨어
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.url} - IP: ${req.ip}`);
    next();
});

const PORT = process.env.PORT || 3000;

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// 테이블명을 상수로 정의
const TABLES = {
    USER: 'SFMARK1.user',
    DIARY: 'SFMARK1.diary'
};

// 서버 시작 전에 필수 환경 변수 확인
const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_DATABASE'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
    console.error(`Missing required environment variables: ${missingEnvVars.join(', ')}`);
    process.exit(1);
}

// GET 요청 

// 기본 경로에 대한 요청 처리
app.get('/', (req, res) => {
    res.send('Express 서버가 실행 중입니다!');
});

// 임시 데이터 (without DB)
app.get('/data', (req, res) => {
    const jsonData = {
        id: 1,
        name: 'John Doe',
        email: 'johndoe@example.com'
    };
    res.json(jsonData);
});

// USERS 정보 테스트
app.get('/api/users', (req, res) => {
    db.query('SELECT * FROM SFMARK1.test_table;', (err, results) => {
        if (err) {
            logger.error('쿼리 실행 중 오류 발생:', { error: err.message, stack: err.stack });
            res.status(500).send('500 서버 오류');
            return;
        }
        logger.info('사용자 목록 조회 성공');
        res.json(results);
    });
});

// 모든 DIARY 게시글 정보 가져오기
app.get('/api/diary', (req, res) => {
    db.query(`SELECT * FROM ${TABLES.DIARY}`, (err, results) => {
        if (err) {
            console.error('쿼리 실행 중 오류 발생:', err);
            res.status(500).send('500 서버 오류');
            return;
        }
        res.json(results);
    });
});

// 특정 DIARY 게시글 정보 가져오기
app.get('/api/diary/:id', async (req, res) => {
    try {
        const diaryId = req.params.id;
        const query = `SELECT * FROM ${TABLES.DIARY} WHERE post_id = ?`;
        const results = await executeQuery(query, [diaryId]);
        
        if (results.length === 0) {
            return res.status(404).send('게시글을 찾을 수 없습니다.');
        }
        res.json(results[0]);
    } catch (err) {
        console.error('쿼리 실행 중 오류 발생:', err);
        res.status(500).send('500 서버 오류');
    }
});


// POST요청

// 회원가입 요청 처리
app.post('/api/signup', async (req, res) => {
    const { email_adress, password, username, marketing_agree } = req.body;
    
    // 이메일 형식 검증
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email_adress)) {
        return res.status(400).json({ message: '올바른 이메일 형식이 아닙니다.' });
    }
    
    // 비밀번호 길이 검증
    if (password.length < 8) {
        return res.status(400).json({ message: '비밀번호는 최소 8자 이상이어야 합니다.' });
    }
    
    const created_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
  
    try {
        const password_hash = await bcrypt.hash(password, 10);

        // MySQL INSERT 쿼리
        const query = `
            INSERT INTO SFMARK1.user (email_adress, password_hash, username, marketing_agree, created_at)
            VALUES (?, ?, ?, ?, ?)
        `;
        
        db.query(query, [
            email_adress,
            password_hash,
            username,
            marketing_agree ? 1 : 0,  // BIT(1) 필드에 맞게 1 또는 0으로 변환
            created_at
        ], (err, result) => {
            if (err) {
                console.error("회원가입 중 오류:", err);
                return res.status(500).send("회원가입 중 오류가 발생했습니다.");
            }
            res.status(200).send("회원가입이 성공적으로 완료되었습니다.");
        });
    } catch (error) {
        console.error("서버 오류:", error);
        res.status(500).send("서버 오류가 발생했습니다.");
    }
});

// 로그인 POST 요청 처리
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    // 사용자 조회 쿼리
    const query = 'SELECT * FROM SFMARK1.user WHERE email_address = ?';
    
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error("데이터베이스 오류:", err);
            return res.status(500).send("서버 오류가 발생했습니다.");
        }
        
        if (results.length === 0) {
            return res.status(400).send("사용자를 찾을 수 없습니다.");
        }
        
        const user = results[0];

        // 비밀번호 비교
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).send("비밀번호가 일치하지 않습니다.");
        }

        // JWT 토큰 생성
        const token = jwt.sign(
            { userId: user.user_id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "1h" } // 토큰 만료 시간
        );

        res.status(200).json({ token });
    });
});



// 게시글 저장을 위한 POST 요청 처리
app.post('/api/diary', (req, res) => {
    const { post_title, post_category, author, content } = req.body;

    const query = `INSERT INTO ${TABLES.DIARY} 
        (post_title, post_category, author, post_content, create_date) 
        VALUES (?, ?, ?, ?, NOW())`;

    db.query(query, [post_title, post_category, author, content], (err, result) => {
      if (err) {
        console.error('데이터 삽입 오류:', err);
        return res.status(500).send('서버 오류');
      }
      res.status(200).send('게시글이 성공적으로 저장되었습니다.');
    });
  });



// PUT 요청

// 게시글 저장을 위한 PUT 요청 처리
app.put('/api/diary/:id', (req, res) => {
    const { id } = req.params;
    const { post_title, post_category, author, post_content } = req.body;

    if (!post_title || !post_category || !author || !post_content) {
      return res.status(400).send('모든 필드를 올바르게 입력해야 합니다.');
    }

    const query = `
      UPDATE SFMARK1.diary 
      SET post_title = ?, post_category = ?, author = ?, post_content = ?, update_date = NOW()
      WHERE post_id = ?
    `;

    db.query(query, [post_title, post_category, author, post_content, id], (err, result) => {
      if (err) {
        console.error('데이터 수정 오류:', err);
        return res.status(500).send('서버 오류');
      }

      if (result.affectedRows === 0) {
        return res.status(404).send('해당 ID의 게시글을 찾을 수 없습니다.');
      }

      res.status(200).send('게시글이 성공적으로 수정되었습니다.');
    });
});


// 주기적으로 연결을 유지하는 쿼리 (선택 사항)
setInterval(() => {
    db.query('SELECT 1', (err) => {
        if (err) {
            console.error('연결 유지 쿼리 중 오류 발생:', err);
        }
    });
}, 10000); // 10초마다 실행

// 서버 시작
app.listen(PORT, () => {
    logger.info(`Server is running on http://localhost:${PORT}`);
});

// 에러 핸들링
process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception:', { error: err.message, stack: err.stack });
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', { 
        reason: reason instanceof Error ? reason.message : reason,
        stack: reason instanceof Error ? reason.stack : undefined
    });
});

// 공통 에러 핸들러 추가
app.use((err, req, res, next) => {
    logger.error('에러 발생:', { 
        error: err.message, 
        stack: err.stack,
        path: req.path,
        method: req.method
    });
    
    res.status(500).json({
        message: '서버 오류가 발생했습니다.',
        error: process.env.NODE_ENV === 'development' ? err.message : {}
    });
});

// db.query를 Promise로 래핑하여 사용하는 것을 추천
const executeQuery = (sql, params) => {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
            if (err) reject(err);
            resolve(results);
        });
    });
};

// 응답 형식을 일관되게 유지
const sendResponse = (res, status, message, data = null) => {
    const response = {
        status,
        message,
        data
    };
    return res.status(status).json(response);
};

// 사용 예시
app.post('/api/signup', async (req, res) => {
    try {
        // ... 처리 로직
        return sendResponse(res, 200, "회원가입이 성공적으로 완료되었습니다.");
    } catch (error) {
        return sendResponse(res, 500, "서버 오류가 발생했습니다.");
    }
});

