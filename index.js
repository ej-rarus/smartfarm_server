// index.js
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
require('dotenv').config(); // dotenv 패키지 불러오기

const app = express();

// 포트 설정
const PORT = 3000;

// MySQL 연결 설정 (환경 변수 사용)
const db = mysql.createConnection({
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

// MySQL 연결
db.connect((err) => {
    if (err) {
        console.error('MySQL 연결 실패:', err);
        return;
    }
    console.log('MySQL에 성공적으로 연결되었습니다.');
});

// 라우터

// 기본 경로에 대한 요청 처리
app.get('/', (req, res) => {
    res.send('Express 서버가 실행 중입니다!');
});

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

// 임시 데이터
app.get('/data', (req, res) => {
    const jsonData = {
        id: 1,
        name: 'John Doe',
        email: 'johndoe@example.com'
    };
    res.json(jsonData);
});


app.post('/db', (req, res)=>{
    const { test_name, test_date } = req.body;
    const query = 'INSERT INTO test_table (test_name, test_date) VALUES (?, ?)';
    db.query(query, [test_name, test_date], (err, result) => {
        if (err) {
            console.error('데이터 삽입 오류:', err);
            res.status(500).send('서버 오류');
        } else {
            res.status(200).send('사용자 데이터가 성공적으로 저장되었습니다.');
        }
    });
})

// 서버 시작
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
