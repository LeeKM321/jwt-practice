-- 테스트 사용자
INSERT INTO users (email, password, name, role, created_at)
VALUES ('user@example.com', '$2a$10$XPTvLhT.FEHj6g3qE7YXqezqGVoEcMxHzaG.YdYjS5jKcHfY4wz0a', '일반유저', 'USER',
        CURRENT_TIMESTAMP),
       ('admin@example.com', '$2a$10$XPTvLhT.FEHj6g3qE7YXqezqGVoEcMxHzaG.YdYjS5jKcHfY4wz0a', '관리자', 'ADMIN',
        CURRENT_TIMESTAMP),
       ('hong@example.com', '$2a$10$XPTvLhT.FEHj6g3qE7YXqezqGVoEcMxHzaG.YdYjS5jKcHfY4wz0a', '홍길동', 'USER',
        CURRENT_TIMESTAMP),
       ('kim@example.com', '$2a$10$XPTvLhT.FEHj6g3qE7YXqezqGVoEcMxHzaG.YdYjS5jKcHfY4wz0a', '김철수', 'USER',
        CURRENT_TIMESTAMP);

-- 테스트 게시글
INSERT INTO posts (title, content, author_id, created_at, updated_at)
VALUES ('Spring Boot와 JWT 인증', 'JWT를 사용하면 Stateless한 인증을 구현할 수 있습니다.', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
       ('RESTful API 설계 원칙', 'REST API를 설계할 때 지켜야 할 원칙들을 알아봅시다.', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
       ('Spring Security 완벽 가이드', 'Spring Security의 핵심 개념과 사용법을 정리했습니다.', 3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
       ('Java 17의 새로운 기능들', 'Java 17에서 추가된 Record, Sealed Class 등을 알아봅시다.', 3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
       ('관리자 공지사항', '시스템 점검이 예정되어 있습니다.', 2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);