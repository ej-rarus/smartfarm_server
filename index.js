const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use(express.json());
app.use(cors());

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

// 기본 GET 요청
app.get('/', (req, res) => {
    res.send('Express 서버가 실행 중입니다!');
});

// 회원가입 요청 처리
app.post('/api/signup', async (req, res) => {
    const { email_adress, password, username, marketing_agree } = req.body;
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

// 특정 DIARY 게시글 정보 가져오기
app.get('/api/diary/:id', (req, res) => {
    const diaryId = req.params.id;
    const query = 'SELECT * FROM SFMARK1.diary WHERE post_id = ?;';
    db.query(query, [diaryId], (err, results) => {
        if (err) {
            console.error('쿼리 실행 중 오류 발생:', err);
            return res.status(500).send('500 서버 오류');
        }
        if (results.length === 0) {
            return res.status(404).send('게시글을 찾을 수 없습니다.');
        }
        res.json(results[0]);
    });
});

// 연결 유지용 쿼리 (주기적 실행)
setInterval(() => {
    db.query('SELECT 1', (err) => {
        if (err) console.error('연결 유지 쿼리 중 오류 발생:', err);
    });
}, 60000); // 60초마다 실행

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
