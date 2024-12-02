const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();
const helmet = require('helmet');
const logger = require('./logger');
const jwt = require('jsonwebtoken');
const axios = require('axios'); 
const http = require('http');
const { WebSocketServer } = require("ws");
const { Configuration, OpenAIApi } = require('openai');

// OpenAI 설정
const configuration = new Configuration({
    apiKey: process.env.OPENAI_API_KEY,
});
const openai = new OpenAIApi(configuration);

const app = express();
app.use(express.json());
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

// Helmet 미들웨어 추가
app.use(helmet({
    contentSecurityPolicy: false,  // CSP를 비활성화하거나
    crossOriginEmbedderPolicy: false
}));

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
const requiredEnvVars = [
    'DB_HOST', 
    'DB_USER', 
    'DB_PASSWORD', 
    'DB_DATABASE',
    'JWT_SECRET',
    'KAMIS_CERT_KEY',  
    'KAMIS_API_ID'     
];
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

// KAMIS API 프록시 라우트 추가
app.get('/api/kamis/price', async (req, res) => {
    try {
        const { crop_code = '225' } = req.query;  // 기본값으로 토마토 설정
        const today = new Date();
        const endDate = today.toISOString().split('T')[0];
        const startDate = new Date(today.setMonth(today.getMonth() - 1))
                          .toISOString().split('T')[0];

        logger.info(`KAMIS API 요청: crop_code=${crop_code}, startDate=${startDate}, endDate=${endDate}`);

        const response = await axios.get('http://www.kamis.or.kr/service/price/xml.do', {
            params: {
                action: 'periodProductList',
                p_productclscode: '02',
                p_startday: startDate,
                p_endday: endDate,
                p_itemcategorycode: '200',
                p_itemcode: crop_code,
                p_kindcode: '00',
                p_productrankcode: '04',
                p_countrycode: '1101',
                p_convert_kg_yn: 'Y',
                p_cert_key: process.env.KAMIS_CERT_KEY,
                p_cert_id: process.env.KAMIS_API_ID,
                p_returntype: 'json'
            }
        });

        // 응답 데이터가 없는 경우에도 빈 배열 반환
        if (response.data && response.data.data) {
            logger.info('KAMIS API 데이터 조회 성공');
            
            const formattedData = {
                status: 200,
                message: "데이터 조회 성공",
                data: {
                    data: {
                        item: response.data.data.item || []  // 데이터가 없으면 빈 배열
                    }
                }
            };
            
            return res.status(200).json(formattedData);
        } else {
            // 데이터가 없어도 200 응답과 빈 배열 반환
            logger.info('KAMIS API 데이터 없음 - 빈 배열 반환');
            return res.status(200).json({
                status: 200,
                message: "데이터 조회 성공",
                data: {
                    data: {
                        item: []
                    }
                }
            });
        }

    } catch (error) {
        logger.error('KAMIS API 호출 중 오류:', { 
            error: error.message, 
            stack: error.stack,
            params: req.query
        });
        
        // 서버 에러의 경우에만 500 반환
        return res.status(500).json({
            status: 500,
            message: "가격 정보 조회 중 오류가 발생했습니다.",
            data: {
                data: {
                    item: []
                }
            }
        });
    }
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
            logger.error('쿼리 실행 중 오류 발생:', err);
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
    try {
        const { email_adress, password } = req.body;

        // 입력값 검증
        if (!email_adress || !password) {
            return sendResponse(res, 400, "이메일과 비밀번호를 모두 입력해주세요.");
        }

        // 사용자 조회
        const query = `SELECT * FROM ${TABLES.USER} WHERE email_adress = ?`;
        const results = await executeQuery(query, [email_adress]);

        if (results.length === 0) {
            logger.info(`로그인 실패: 존재하지 않는 이메일 - ${email_adress}`);
            return sendResponse(res, 401, "이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        const user = results[0];

        // 비밀번호 검증
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
            logger.info(`로그인 실패: 잘못된 비밀번호 - ${email_adress}`);
            return sendResponse(res, 401, "이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        // JWT 토큰 생성
        const token = jwt.sign(
            {
                userId: user.user_id,
                email: user.email_adress,
                username: user.username
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // 마지막 로그인 시간 업데이트
        await executeQuery(
            `UPDATE ${TABLES.USER} SET last_login = NOW() WHERE user_id = ?`,
            [user.user_id]
        );

        logger.info(`로그인 성공: ${email_adress}`);
        
        // 응답
        return sendResponse(res, 200, "로그인 성공", {
            token,
            user: {
                userId: user.user_id,
                email: user.email_adress,
                username: user.username
            }
        });

    } catch (error) {
        logger.error('로그인 처리 중 오류 발생:', { 
            error: error.message, 
            stack: error.stack 
        });
        return sendResponse(res, 500, "로그인 처리 중 오류가 발생했습니다.");
    }
});

// JWT 검증 미들웨어 (보호된 라우트에서 사용)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return sendResponse(res, 401, "인증 토큰이 필요합니다.");
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            logger.error('토큰 검증 실패:', { error: err.message });
            return sendResponse(res, 403, "유효하지 않은 토큰입니다.");
        }

        req.user = user;
        next();
    });
};

// 보호된 라우트 예시
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        const query = `SELECT user_id, email_adress, username, created_at 
                      FROM ${TABLES.USER} 
                      WHERE user_id = ?`;
        const results = await executeQuery(query, [userId]);
        
        if (results.length === 0) {
            return sendResponse(res, 404, "사용자를 찾을 수 없습니다.");
        }

        return sendResponse(res, 200, "프로필 조회 성공", results[0]);
    } catch (error) {
        logger.error('프로필 조회 중 오류 발생:', { 
            error: error.message, 
            stack: error.stack 
        });
        return sendResponse(res, 500, "프로필 조회 중 오류가 발생했습니다.");
    }
});

// 게시글 저장을 위한 POST 요청 처리
app.post('/api/diary', authenticateToken, async (req, res) => {
    const { post_title, post_category, author, content } = req.body;
    
    if (!post_title || !post_category || !author || !content) {
        return sendResponse(res, 400, "모든 필수 필드를 입력해주세요.");
    }

    const query = `INSERT INTO ${TABLES.DIARY} 
        (post_title, post_category, author, post_content, create_date) 
        VALUES (?, ?, ?, ?, NOW())`;
    await executeQuery(query, [post_title, post_category, author, content]);
    return sendResponse(res, 200, "게시글이 성공적으로 저장되었습니다.");
});



// PUT 요청

// 게시글 저장을 위한 PUT 요청 처리
app.put('/api/diary/:id', authenticateToken, (req, res) => {
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

// WebSocket 서버 생성
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// WebSocket 연결 관리
let clients = [];
wss.on("connection", (ws) => {
    console.log("Client connected");
    clients.push(ws);

    // 클라이언트가 메시지를 보낼 때 처리
    ws.on("message", (message) => {
        const messageStr = message.toString();  // Buffer를 문자열로 변환
        console.log("Received:", messageStr);

        // 모든 클라이언트에게 받은 메시지를 브로드캐스트
        clients.forEach((client) => {
            if (client.readyState === client.OPEN) {
                client.send(messageStr);  // 실제 받은 메시지를 전송
            }
        });
    });

    // 연결이 끊어졌을 때
    ws.on("close", () => {
        console.log("Client disconnected");
        clients = clients.filter((client) => client !== ws);
    });
});

// WebSocket 에러 처리 추가
wss.on("error", (error) => {
    logger.error('WebSocket 서버 에러:', { 
        error: error.message, 
        stack: error.stack 
    });
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`WebSocket Server is running on ws://localhost:${PORT}`);
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

// 챗봇 엔드포인트 추가
app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message) {
            return sendResponse(res, 400, "메시지를 입력해주세요.");
        }

        const completion = await openai.createChatCompletion({
            model: "gpt-3.5-turbo",
            messages: [
                {
                    role: "system",
                    content: "당신은 스마트팜 관련 전문가입니다. 농작물 재배, 환경 관리, 질병 관리 등에 대해 도움을 주세요."
                },
                {
                    role: "user",
                    content: message
                }
            ],
            temperature: 0.7,
            max_tokens: 1000
        });

        const botResponse = completion.data.choices[0].message.content;
        return sendResponse(res, 200, "성공", { message: botResponse });

    } catch (error) {
        logger.error('챗봇 응답 생성 중 오류:', { 
            error: error.message, 
            stack: error.stack 
        });
        return sendResponse(res, 500, "챗봇 응답 생성 중 오류가 발생했습니다.");
    }
});