const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// 로그 포맷 정의
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => {
        return `${timestamp} ${level}: ${message}`;
    })
);

// 로거 생성
const logger = winston.createLogger({
    format: logFormat,
    transports: [
        // 콘솔 출력
        new winston.transports.Console(),
        
        // 일반 로그 파일
        new DailyRotateFile({
            level: 'info',
            dirname: 'logs',
            filename: 'application-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '14d'
        }),
        
        // 에러 로그 파일
        new DailyRotateFile({
            level: 'error',
            dirname: 'logs/error',
            filename: 'error-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '14d'
        })
    ]
});

module.exports = logger; 