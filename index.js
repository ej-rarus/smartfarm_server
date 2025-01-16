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
const OpenAI = require('openai');
const path = require('path');
const multer = require('multer');
const fs = require('fs');




// uploads 디렉토리 확인 및 생성
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)){
    fs.mkdirSync(uploadsDir);
}

// multer 설정
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('이미지 파일만 업로드 가능합니다.'), false);
    }
};

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB 제한
    },
    fileFilter: fileFilter
});

// OpenAI 설정
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

// 2. 앱 초기화 및 미들웨어 설정
const app = express();
app.use(express.json());
app.use(cors({
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:3000',
            'http://3.39.126.121:3000',
            'http://farmster.co.kr',
            'https://farmster.co.kr'
        ];
        
        // origin이 없거나 허용된 도메인인 경우
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    exposedHeaders: ['Content-Type', 'Authorization']
}));

// Helmet 미들웨어 추가
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "blob:", "*"],
            connectSrc: ["'self'", "*"],
        }
    }
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



// 모든 DIARY 게시글 정보 가져오기 (is_delete가 false인 것만)
app.get('/api/diary', async (req, res) => {
    try {
        const query = `
            SELECT post_id, post_title, post_category, author, post_content, 
                   create_date, update_date, image 
            FROM ${TABLES.DIARY} 
            WHERE is_delete = false 
            ORDER BY create_date DESC`;
        const results = await executeQuery(query);
        return sendResponse(res, 200, "게시글 목록 조회 성공", results);
    } catch (err) {
        logger.error('게시글 조회 중 오류 발생:', err);
        return sendResponse(res, 500, "게시글 조회 중 오류가 발생했습니다.");
    }
});

// 특정 DIARY 게시글 정보 가져오기
app.get('/api/diary/:id', async (req, res) => {
    try {
        const diaryId = req.params.id;
        const query = `
            SELECT post_id, post_title, post_category, author, post_content, 
                   create_date, update_date, image 
            FROM ${TABLES.DIARY} 
            WHERE post_id = ? AND is_delete = false`;
        const results = await executeQuery(query, [diaryId]);
        
        if (results.length === 0) {
            return sendResponse(res, 404, "게시글을 찾을 수 없습니다.");
        }

        // 이미지 경로가 있는 경우 전체 URL로 변환
        const post = results[0];
        if (post.image) {
            post.image = `/uploads/${post.image}`;
        }

        return sendResponse(res, 200, "게시글 조회 성공", post);
    } catch (err) {
        logger.error('게시글 조회 중 오류 발생:', err);
        return sendResponse(res, 500, "게시글 조회 중 오류가 발생했습니다.");
    }
});


// POST요청

// 회원가입 요청 처리
app.post('/api/signup', async (req, res) => {
    try {
        const { email_adress, password, username, marketing_agree } = req.body;
        
        // 디버깅을 위한 요청 데이터 로깅
        logger.info('회원가입 요청 데이터:', {
            email_adress,
            username,
            marketing_agree,
            hasPassword: !!password
        });
        
        // 필수 필드 개별 검증
        if (!email_adress) {
            return res.status(400).json({
                status: 400,
                message: '이메일 주소를 입력해주세요.',
                data: null
            });
        }

        if (!password) {
            return res.status(400).json({
                status: 400,
                message: '비밀번호를 입력해주세요.',
                data: null
            });
        }

        if (!username) {
            return res.status(400).json({
                status: 400,
                message: '사용자 이름을 입력해주세요.',
                data: null
            });
        }
        
        // 이메일 형식 검증
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email_adress)) {
            return res.status(400).json({
                status: 400,
                message: '올바른 이메일 형식이 아닙니다.',
                data: null
            });
        }
        
        // 비밀번호 검증 (간단한 버전으로 수정)
        if (password.length < 8) {
            return res.status(400).json({
                status: 400,
                message: '비밀번호는 최소 8자 이상이어야 합니다.',
                data: null
            });
        }

        // 이메일 중복 검사
        const checkEmailQuery = 'SELECT user_id FROM SFMARK1.user WHERE email_adress = ?';
        const [existingUser] = await executeQuery(checkEmailQuery, [email_adress]);
        
        if (existingUser) {
            return res.status(409).json({
                status: 409,
                message: '이미 사용 중인 이메일입니다.',
                data: null
            });
        }

        const password_hash = await bcrypt.hash(password, 10);
        
        // MySQL INSERT 쿼리
        const query = `
            INSERT INTO SFMARK1.user (
                email_adress, 
                password_hash, 
                username, 
                marketing_agree, 
                created_at,
                updated_at,
                role_id
            ) VALUES (?, ?, ?, ?, NOW(), NOW(), 1)
        `;
        
        const result = await executeQuery(query, [
            email_adress,
            password_hash,
            username,
            marketing_agree ? 1 : 0
        ]);

        logger.info('회원가입 성공:', { 
            user_id: result.insertId,
            email_adress, 
            username 
        });

        return res.status(201).json({
            status: 201,
            message: '회원가입이 성공적으로 완료되었습니다.',
            data: {
                user_id: result.insertId,
                email_adress,
                username
            }
        });

    } catch (error) {
        logger.error('회원가입 중 오류:', error);
        return res.status(500).json({
            status: 500,
            message: '서버 오류가 발생했습니다.',
            data: null,
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
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
app.post('/api/diary', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { post_title, post_category, author, post_content } = req.body;
        
        // 입력값 검증
        if (!post_title || !post_category || !author || !post_content) {
            return res.status(400).json({
                status: 400,
                message: "필수 필드를 모두 입력해주세요.",
                data: null
            });
        }

        // 이미지 파일 처리
        let imagePath = null;
        if (req.file) {
            imagePath = req.file.filename;
            logger.info('이미지 업로드 성공:', imagePath);
        }

        // 데이터베이스에 저장
        const query = `
            INSERT INTO ${TABLES.DIARY} 
            (post_title, post_category, author, post_content, image, create_date, is_delete) 
            VALUES (?, ?, ?, ?, ?, NOW(), false)
        `;
            
        const result = await executeQuery(query, [
            post_title, 
            post_category, 
            author, 
            post_content, 
            imagePath
        ]);

        logger.info('게시글 저장 성공:', result);

        return res.status(200).json({
            status: 200,
            message: "게시글이 성공적으로 저장되었습니다.",
            data: {
                post_id: result.insertId,
                image: imagePath
            }
        });

    } catch (error) {
        logger.error('게시글 저장 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "게시글 저장 중 오류가 발생했습니다.",
            data: null
        });
    }
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

        // 모든 클라이언트에게 받은 메시지 브로드캐스트
        clients.forEach((client) => {
            if (client.readyState === client.OPEN) {
                client.send(messageStr);  // 실제 받은 메시지를 전송
            }
        });
    });

    // 연결이 끊어질 때
    ws.on("close", () => {
        console.log("Client disconnected");
        clients = clients.filter((client) => client !== ws);
    });

    // WebSocket 연결에 대한 에러 처리 추가
    ws.on("error", (error) => {
        logger.error('WebSocket 클라이언트 에러:', { 
            error: error.message, 
            stack: error.stack 
        });
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



// 챗봇 엔드포인트 추가
app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        
        // 메시지 유효성 검사
        if (!message) {
            return sendResponse(res, 400, "메시지를 입력해주세요.");
        }

        // OpenAI API 키 확인
        if (!process.env.OPENAI_API_KEY) {
            logger.error('OpenAI API 키가 설정되지 않았습니다.');
            return sendResponse(res, 500, "서버 설정 오류가 발생했습니다.");
        }

        logger.info('챗봇 요청:', { message });

        try {
            const completion = await openai.chat.completions.create({
                model: "ft:gpt-4o-2024-08-06:personal:janghyupbot:AZsvPYfT",
                messages: [
                    {
                        role: "system",
                        content: "너는 이제 장협봇이야. 농사에 대해서 특히 스마트팜에 대해서 모르는 게 없지만 엄청 예민하고 까칠해. 농작물 재배, 환경 관리, 질병 관리 등에 대해 도움을 주면돼. 말투는 이런식이래:  왜요 / 뭐가 문제인데 / 시들었어요? 물 줘요 / 물 많아요? 그럼 과습인가보죠 / 또 시작이네 아으 / 당연한 질문은 하지 마시라고요 으으으!!"
                    },
                    {
                        role: "user",
                        content: message
                    },
                ],
            });

            // API 응답 로깅 추가
            logger.info('OpenAI API 응답:', completion.choices[0]);

            const botResponse = completion.choices[0].message;
            logger.info('챗봇 응답 성공');
            
            // 응답 구조 수정
            return res.status(200).json({
                status: 200,
                message: "성공",
                data: botResponse
            });

        } catch (openaiError) {
            logger.error('OpenAI API 호출 오류:', { 
                error: openaiError.message, 
                stack: openaiError.stack 
            });
            return sendResponse(res, 500, "AI 응답 중 오류가 발생했습니다.");
        }

    } catch (error) {
        logger.error('챗봇 처리 중 오류:', { 
            error: error.message, 
            stack: error.stack 
        });
        return sendResponse(res, 500, "챗봇 응답 생성 중 오류가 발생했습니다.");
    }
});

// 정적 파일 제공을 위한 미들웨어 추가
app.use('/uploads', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    next();
}, express.static(path.join(__dirname, 'uploads')));

// 작물 게시글 추가 엔드포인트
app.post('/api/crop-post', authenticateToken, upload.single('post_img'), async (req, res) => {
    try {
        const { crop_id, post_text } = req.body;
        const user_id = req.user.userId;

        // 입력값 검증
        if (!crop_id || !post_text) {
            return res.status(400).json({
                status: 400,
                message: "필수 필드를 모두 입력해주세요. (작물 ID, 게시글 내용)",
                data: null
            });
        }

        // 작물 ID 유효성 검증
        const cropCheckQuery = `
            SELECT id FROM my_crop 
            WHERE id = ? AND user_id = ?
        `;
        const cropCheck = await executeQuery(cropCheckQuery, [crop_id, user_id]);
        
        if (cropCheck.length === 0) {
            // 업로드된 파일이 있다면 삭제
            if (req.file) {
                fs.unlink(req.file.path, (err) => {
                    if (err) logger.error('파일 삭제 실패:', err);
                });
            }
            return res.status(404).json({
                status: 404,
                message: "유효하지 않은 작물 ID입니다.",
                data: null
            });
        }

        // 이미지 파일 처리
        let imageUrl = null;
        if (req.file) {
            imageUrl = `/uploads/${req.file.filename}`;  // DB에 저장될 URL 경로
            logger.info('이미지 업로드 성공:', imageUrl);
        }

        // 게시글 저장
        const query = `
            INSERT INTO crop_post 
            (user_id, crop_id, post_img, post_text, created_at)
            VALUES (?, ?, ?, ?, NOW())
        `;

        const result = await executeQuery(query, [
            user_id,
            crop_id,
            imageUrl,  // URL 경로 저장
            post_text
        ]);

        logger.info('작물 게시글 추가 성공:', result);

        return res.status(200).json({
            status: 200,
            message: "게시글이 성공적으로 추가되었습니다.",
            data: {
                id: result.insertId,
                user_id,
                crop_id,
                post_img: imageUrl,  // 전체 URL 경로 반환
                post_text,
                created_at: new Date()
            }
        });

    } catch (error) {
        // 에러 발생 시 업로드된 파일 삭제
        if (req.file) {
            fs.unlink(req.file.path, (err) => {
                if (err) logger.error('파일 삭제 실패:', err);
            });
        }

        logger.error('게시글 추가 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "게시글 추가 중 오류가 발생했습니다.",
            data: null
        });
    }
});

// GET /api/mycrop - 사용자의 모든 작물 조회
app.get('/api/mycrop', authenticateToken, async (req, res) => {
    try {
        const user_id = req.user.userId;

        const query = `
            SELECT 
                id,
                user_id,
                species,  
                nickname,
                planted_at,  
                harvest_at,
                created_at,
                updated_at
            FROM SFMARK1.my_crop 
            WHERE user_id = ? 
            AND is_deleted = false 
            ORDER BY created_at DESC
        `;

        const results = await executeQuery(query, [user_id]);

        // 날짜 형식 변환 및 필드명 매핑
        const formattedResults = results.map(crop => ({
            id: crop.id,
            species: crop.species,
            nickname: crop.nickname,
            planted_at: crop.planted_at,
            harvest_at: crop.harvest_at,  
            created_at: crop.created_at,
            image_url: null
        }));

        logger.info(`사용자 ${user_id}의 작물 목록 조회 성공`);
        return res.status(200).json(formattedResults);

    } catch (error) {
        logger.error('작물 목록 조회 중 오류 발생:', error);
        return res.status(500).json({
            message: "작물 목록 조회 중 오류가 발생했습니다."
        });
    }
});

// GET /api/mycrop/:crop_id/posts - 특정 작물의 모든 게시글 조회
app.get('/api/mycrop/:crop_id/posts', authenticateToken, async (req, res) => {
    try {
        const user_id = req.user.userId;
        const crop_id = req.params.crop_id;

        console.log('요청 받은 파라미터:', { user_id, crop_id });

        // 1. 작물 확인 쿼리
        const cropCheckQuery = `
            SELECT id FROM my_crop 
            WHERE id = ? AND user_id = ? AND is_deleted = false
        `;
        
        console.log('작물 확인 쿼리:', cropCheckQuery);
        const cropCheck = await executeQuery(cropCheckQuery, [crop_id, user_id]);
        console.log('작물 확인 결과:', cropCheck);

        if (cropCheck.length === 0) {
            return res.status(404).json({
                status: 404,
                message: "해당 작물을 찾을 수 없습니다.",
                data: null
            });
        }

        // 2. 게시글 조회 쿼리
        const query = `
            SELECT 
                id,
                user_id,
                crop_id,
                post_img,
                post_text,
                created_at,
                updated_at,
                is_deleted,
                likes_id
            FROM crop_post
            WHERE crop_id = ? 
            AND is_deleted = false
            ORDER BY created_at DESC
        `;

        console.log('게시글 조회 쿼리:', query);
        const posts = await executeQuery(query, [crop_id]);
        console.log('조회된 게시글:', posts);

        return res.status(200).json({
            status: 200,
            message: "게시글 목록 조회 성공",
            data: posts
        });

    } catch (error) {
        console.error('상세 에러 정보:', {
            message: error.message,
            stack: error.stack,
            code: error.code,
            sqlMessage: error.sqlMessage,
            sqlState: error.sqlState
        });

        return res.status(500).json({
            status: 500,
            message: "게시글 목록 조회 중 오류가 발생했습니다.",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// POST /api/mycrop - 새로운 작물 추가
app.post('/api/mycrop', authenticateToken, async (req, res) => {
    try {
        const { species, nickname, planted_at, harvest_at } = req.body;
        const user_id = req.user.userId;  // JWT 토큰에서 사용자 ID 추출

        // 필수 필드 검증
        if (!species || !nickname || !planted_at) {
            return res.status(400).json({
                status: 400,
                message: "필수 필드를 모두 입력해주세요. (작물 종류, 별명, 심은 날짜)",
                data: null
            });
        }

        // 날짜 형식 검증 (YYYY-MM-DD)
        const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateRegex.test(planted_at) || (harvest_at && !dateRegex.test(harvest_at))) {
            return res.status(400).json({
                status: 400,
                message: "날짜는 YYYY-MM-DD 형식이어야 합니다.",
                data: null
            });
        }

        // 새 작물 추가
        const query = `
            INSERT INTO SFMARK1.my_crop 
            (user_id, species, nickname, planted_at, harvest_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, NOW(), NOW())
        `;

        const result = await executeQuery(query, [
            user_id,
            species,
            nickname,
            planted_at,
            harvest_at || null
        ]);

        logger.info('새로운 작물 추가 성공:', result);

        // 추가된 작물 정보 조회
        const newCrop = await executeQuery(
            'SELECT * FROM SFMARK1.my_crop WHERE id = ?',
            [result.insertId]
        );

        return res.status(201).json({
            status: 201,
            message: "작물이 성공적으로 추가되었습니다.",
            data: {
                id: result.insertId,
                user_id,
                species,
                nickname,
                planted_at,
                harvest_at: harvest_at || null,
                created_at: new Date(),
                updated_at: new Date(),
            }
        });

    } catch (error) {
        logger.error('작물 추가 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "작물 추가 중 오류가 발생했습니다.",
            data: null
        });
    }
});

// POST /api/mycrop/:crop_id/posts - 새로운 작물 게시글 추가
app.post('/api/mycrop/:crop_id/posts', authenticateToken, upload.single('post_img'), async (req, res) => {
    try {
        const user_id = req.user.userId;
        const crop_id = req.params.crop_id;
        const { post_text } = req.body;

        // 필수 필드 검증
        if (!post_text) {
            // 업로드된 이미지가 있다면 삭제
            if (req.file) {
                fs.unlink(req.file.path, (err) => {
                    if (err) logger.error('파일 삭제 실패:', err);
                });
            }
            return res.status(400).json({
                status: 400,
                message: "게시글 내용은 필수입니다.",
                data: null
            });
        }

        // 작물 소유권 확인
        const cropCheckQuery = `
            SELECT id FROM SFMARK1.my_crop 
            WHERE id = ? AND user_id = ? AND is_deleted = 0
        `;
        const cropCheck = await executeQuery(cropCheckQuery, [crop_id, user_id]);

        if (cropCheck.length === 0) {
            // 업로드된 이미지가 있다면 삭제
            if (req.file) {
                fs.unlink(req.file.path, (err) => {
                    if (err) logger.error('파일 삭제 실패:', err);
                });
            }
            return res.status(404).json({
                status: 404,
                message: "해당 작물을 찾을 수 없습니다.",
                data: null
            });
        }

        // 트랜잭션 시작
        const connection = await db.promise().getConnection();
        await connection.beginTransaction();

        try {
            // 1. crop_post 테이블에 게시글 추가
            const postQuery = `
                INSERT INTO SFMARK1.crop_post 
                (user_id, crop_id, post_img, post_text, created_at, updated_at)
                VALUES (?, ?, ?, ?, NOW(), NOW())
            `;

            const [postResult] = await connection.execute(postQuery, [
                user_id,
                crop_id,
                req.file ? `/uploads/${req.file.filename}` : null,
                post_text
            ]);

            // 2. likes 테이블에 연동 레코드 추가
            const likesQuery = `
                INSERT INTO SFMARK1.likes (likes, post_id)
                VALUES (0, ?)
            `;

            const [likesResult] = await connection.execute(likesQuery, [postResult.insertId]);

            // 3. crop_post 테이블의 likes_id 업데이트
            const updatePostQuery = `
                UPDATE SFMARK1.crop_post 
                SET likes_id = ?
                WHERE id = ?
            `;

            await connection.execute(updatePostQuery, [likesResult.insertId, postResult.insertId]);

            // 트랜잭션 커밋
            await connection.commit();

            logger.info('새로운 게시글 추가 성공:', { postId: postResult.insertId, likesId: likesResult.insertId });

            return res.status(201).json({
                status: 201,
                message: "게시글이 성공적으로 추가되었습니다.",
                data: {
                    id: postResult.insertId,
                    user_id,
                    crop_id,
                    post_img: req.file ? `/uploads/${req.file.filename}` : null,
                    post_text,
                    likes_id: likesResult.insertId,
                    likes: 0,
                    created_at: new Date(),
                    updated_at: new Date()
                }
            });

        } catch (error) {
            // 트랜잭션 롤백
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }

    } catch (error) {
        // 업로드된 이미지가 있다면 삭제
        if (req.file) {
            fs.unlink(req.file.path, (err) => {
                if (err) logger.error('파일 삭제 실패:', err);
            });
        }

        logger.error('게시글 추가 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "게시글 추가 중 오류가 발생했습니다.",
            data: null
        });
    }
});

// GET /api/post/:id - 특정 게시글 상세 정보 조회
app.get('/api/post/:id', authenticateToken, async (req, res) => {
    try {
        const postId = req.params.id;
        const userId = req.user.userId;

        const query = `
            SELECT 
                cp.id,
                cp.user_id,
                cp.crop_id,
                cp.post_img,
                cp.post_text,
                cp.created_at,
                cp.updated_at,
                cp.likes_id,
                l.likes,
                mc.species,
                mc.nickname
            FROM SFMARK1.crop_post cp
            LEFT JOIN SFMARK1.likes l ON cp.likes_id = l.id
            LEFT JOIN SFMARK1.my_crop mc ON cp.crop_id = mc.id
            WHERE cp.id = ? AND cp.is_deleted = false
        `;

        const results = await executeQuery(query, [postId]);

        if (results.length === 0) {
            return res.status(404).json({
                status: 404,
                message: "게시글을 찾을 수 없습니다.",
                data: null
            });
        }

        const post = results[0];
        
        // 이미지 URL이 있는 경우 전체 경로로 변환
        if (post.post_img && !post.post_img.startsWith('http')) {
            post.post_img = `${post.post_img}`;
        }

        return res.status(200).json({
            status: 200,
            message: "게시글 조회 성공",
            data: post
        });

    } catch (error) {
        logger.error('게시글 조회 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "게시글 조회 중 오류가 발생했습니다.",
            data: null
        });
    }
});

// GET /api/user/:id - 특정 사용자 정보 조회
app.get('/api/user/:id', authenticateToken, async (req, res) => {
    try {
        const targetUserId = req.params.id;
        const requestUserId = req.user.userId;

        const query = `
            SELECT 
                user_id,
                username,
                profile_image,
                created_at,
                is_active,
                role_id
            FROM ${TABLES.USER}
            WHERE user_id = ? AND is_active = true
        `;

        const results = await executeQuery(query, [targetUserId]);

        if (results.length === 0) {
            return res.status(404).json({
                status: 404,
                message: "사용자를 찾을 수 없습니다.",
                data: null
            });
        }

        const user = results[0];

        // 프로필 이미지 URL 처리
        if (user.profile_image && !user.profile_image.startsWith('http')) {
            user.profile_image = `${user.profile_image}`; // 필요한 경우 기본 URL 추가
        }

        // 기본 사용자 정보 구성
        const userData = {
            user_id: user.user_id,
            username: user.username,
            profile_image: user.profile_image || null,
            // 자신의 정보를 조회하는 경우에만 추가 정보 제공
            ...(requestUserId === parseInt(targetUserId) && {
                created_at: user.created_at,
                role_id: user.role_id
            })
        };

        return res.status(200).json({
            status: 200,
            message: "사용자 정보 조회 성공",
            data: userData
        });

    } catch (error) {
        logger.error('사용자 정보 조회 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "사용자 정보 조회 중 오류가 발생했습니다.",
            data: null
        });
    }
});

// GET /api/posts - 전체 게시글 목록 조회 (페이지네이션)
app.get('/api/posts', authenticateToken, async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 5;
        const offset = (page - 1) * limit;

        const query = `
            SELECT 
                cp.id,
                cp.user_id,
                cp.crop_id,
                cp.post_img,
                cp.post_text,
                cp.created_at,
                cp.updated_at,
                u.username,
                u.profile_image,
                mc.species,
                mc.nickname,
                COALESCE(l.likes, 0) as likes,
                COALESCE(c.comment_count, 0) as comments
            FROM SFMARK1.crop_post cp
            LEFT JOIN SFMARK1.user u ON cp.user_id = u.user_id
            LEFT JOIN SFMARK1.my_crop mc ON cp.crop_id = mc.id
            LEFT JOIN SFMARK1.likes l ON cp.likes_id = l.id
            LEFT JOIN (
                SELECT post_id, COUNT(*) as comment_count 
                FROM SFMARK1.comments 
                GROUP BY post_id
            ) c ON cp.id = c.post_id
            WHERE cp.is_deleted = false
            ORDER BY cp.created_at DESC
            LIMIT ? OFFSET ?
        `;

        const results = await executeQuery(query, [limit, offset]);

        // 이미지 URL 처리
        const posts = results.map(post => ({
            ...post,
            post_img: post.post_img ? `${post.post_img}` : null,
            profile_image: post.profile_image ? `${post.profile_image}` : null
        }));

        return res.status(200).json({
            status: 200,
            message: "게시글 목록 조회 성공",
            data: posts
        });

    } catch (error) {
        logger.error('게시글 목록 조회 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "게시글 목록 조회 중 오류가 발생했습니다.",
            data: null
        });
    }
});

// POST /api/sensor-data - 센서 데이터 저장
app.post('/api/sensor-data', async (req, res) => {
    try {
        const { sensor_id, temperature, humidity, light_intensity } = req.body;

        // 필수 필드 검증
        if (!sensor_id || temperature == null || humidity == null || light_intensity == null) {
            return res.status(400).json({
                status: 400,
                message: "필수 필드가 누락되었습니다. (sensor_id, temperature, humidity, light_intensity)",
                data: null
            });
        }

        // 데이터 타입 및 범위 검증
        if (typeof temperature !== 'number' || 
            typeof humidity !== 'number' || 
            typeof light_intensity !== 'number') {
            return res.status(400).json({
                status: 400,
                message: "잘못된 데이터 형식입니다. 숫자 형식이어야 합니다.",
                data: null
            });
        }

        // 센서 데이터 저장
        const query = `
            INSERT INTO SFMARK1.sensor_data 
            (sensor_id, temperature, humidity, light_intensity)
            VALUES (?, ?, ?, ?)
        `;

        const result = await executeQuery(query, [
            sensor_id,
            temperature,
            humidity,
            light_intensity
        ]);

        logger.info('센서 데이터 저장 성공:', {
            sensor_id,
            temperature,
            humidity,
            light_intensity
        });

        return res.status(201).json({
            status: 201,
            message: "센서 데이터가 성공적으로 저장되었습니다.",
            data: {
                id: result.insertId,
                sensor_id,
                temperature,
                humidity,
                light_intensity,
                created_at: new Date()
            }
        });

    } catch (error) {
        logger.error('센서 데이터 저장 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "센서 데이터 저장 중 오류가 발생했습니다.",
            data: null
        });
    }
});

// GET /api/sensor-data/:sensorId - 특정 센서의 최근 24시간 데이터 조회
app.get('/api/sensor-data/:sensorId', async (req, res) => {
    try {
        const { sensorId } = req.params;
        
        // 선택적 쿼리 파라미터
        const hours = req.query.hours ? parseInt(req.query.hours) : 24; // 기본값 24시간
        
        const query = `
            SELECT 
                id,
                sensor_id,
                temperature,
                humidity,
                light_intensity,
                created_at
            FROM SFMARK1.sensor_data
            WHERE 
                sensor_id = ?
                AND created_at >= DATE_SUB(NOW(), INTERVAL ? HOUR)
            ORDER BY created_at DESC
        `;

        const results = await executeQuery(query, [sensorId, hours]);

        if (results.length === 0) {
            return res.status(404).json({
                status: 404,
                message: "해당 센서의 데이터가 없습니다.",
                data: null
            });
        }

        // 데이터 가공 및 통계 계산
        const stats = results.reduce((acc, curr) => {
            acc.tempSum += curr.temperature;
            acc.humidSum += curr.humidity;
            acc.lightSum += curr.light_intensity;
            
            acc.tempMax = Math.max(acc.tempMax, curr.temperature);
            acc.tempMin = Math.min(acc.tempMin, curr.temperature);
            acc.humidMax = Math.max(acc.humidMax, curr.humidity);
            acc.humidMin = Math.min(acc.humidMin, curr.humidity);
            acc.lightMax = Math.max(acc.lightMax, curr.light_intensity);
            acc.lightMin = Math.min(acc.lightMin, curr.light_intensity);
            
            return acc;
        }, {
            tempSum: 0, humidSum: 0, lightSum: 0,
            tempMax: -Infinity, tempMin: Infinity,
            humidMax: -Infinity, humidMin: Infinity,
            lightMax: -Infinity, lightMin: Infinity
        });

        const count = results.length;
        const summary = {
            temperature: {
                average: (stats.tempSum / count).toFixed(1),
                max: stats.tempMax.toFixed(1),
                min: stats.tempMin.toFixed(1)
            },
            humidity: {
                average: (stats.humidSum / count).toFixed(1),
                max: stats.humidMax.toFixed(1),
                min: stats.humidMin.toFixed(1)
            },
            light_intensity: {
                average: (stats.lightSum / count).toFixed(1),
                max: stats.lightMax.toFixed(1),
                min: stats.lightMin.toFixed(1)
            }
        };

        return res.status(200).json({
            status: 200,
            message: "센서 데이터 조회 성공",
            data: {
                sensor_id: sensorId,
                summary,
                total_records: count,
                period: `최근 ${hours}시간`,
                records: results
            }
        });

    } catch (error) {
        logger.error('센서 데이터 조회 중 오류 발생:', error);
        return res.status(500).json({
            status: 500,
            message: "센서 데이터 조회 중 오류가 발생했습니다.",
            data: null
        });
    }
});