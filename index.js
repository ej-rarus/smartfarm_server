const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');

require('dotenv').config(); // dotenv 패키지 불러오기

const app = express();
app.use(bodyParser.json());

// 포트 설정
const PORT = 3000;

// MySQL 연결 설정 (환경 변수 사용)
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// CORS 오류 대응
app.use(cors());

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
app.get('/users', (req, res) => {
    db.query('SELECT * FROM SFMARK1.test_table;', (err, results) => {
        if (err) {
            console.error('쿼리 실행 중 오류 발생:', err);
            res.status(500).send('500 서버 오류');
            return;
        }
        res.json(results);
    });
});

// 모든 DIARY 게시글 정보 가져오기
app.get('/diary', (req, res) => {
    db.query('SELECT * FROM SFMARK1.diary;', (err, results) => {
        if (err) {
            console.error('쿼리 실행 중 오류 발생:', err);
            res.status(500).send('500 서버 오류');
            return;
        }
        res.json(results);
    });
});

// 특정 DIARY 게시글 정보 가져오기
app.get('/diary/:id', (req, res) => {
    const diaryId = req.params.id;
    const query = 'SELECT * FROM SFMARK1.diary WHERE post_id = ?;';

    db.query(query, [diaryId], (err, results) => {
        if (err) {
            console.error('쿼리 실행 중 오류 발생:', err);
            res.status(500).send('500 서버 오류');
            return;
        }
        if (results.length === 0) {
            res.status(404).send('게시글을 찾을 수 없습니다.');
            return;
        }
        res.json(results[0]);
    });
});

// POST 요청 테스트
app.post('/db', (req, res) => {
    const { test_name, test_date } = req.body; // JSON 데이터를 파싱
    const query = 'INSERT INTO test_table (test_name, test_date) VALUES (?, ?)';
    db.query(query, [test_name, test_date], (err, result) => {
        if (err) {
            console.error('데이터 삽입 오류:', err);
            res.status(500).send('서버 오류');
        } else {
            res.status(200).send('사용자 데이터가 성공적으로 저장되었습니다.');
        }
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
    console.log(`Server is running on http://localhost:${PORT}`);
});

// 에러 핸들링
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
