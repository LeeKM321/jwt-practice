package com.codeit.jwt.util;

import com.codeit.jwt.config.JwtProperties;
import com.codeit.jwt.domain.user.User;
import com.codeit.jwt.exception.BusinessException;
import com.codeit.jwt.exception.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtUtil {

    private final JwtProperties jwtProperties;

    private SecretKey getSecretKey() {
        byte[] keyBytes = jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8);
        // 비밀키로 HMAC-SHA256 알고리즘을 활용한 서명 생성
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Access Token 생성
    public String generateAccessToken(User user) {

        // Jwts.builder가 Date 객체로 날짜를 세팅하기 때문에 부득이하게 Date로 생성
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtProperties.getAccessTokenExpiration());

        return Jwts.builder()
                .header()
                    .type("JWT")
                    .and()
                .issuer(jwtProperties.getIssuer()) // 발급자 (iss)
                .subject(user.getEmail()) // 주체, 사용자 식별자 (sub)
                .issuedAt(now) // 발급 시간 (iat)
                .expiration(expiryDate) // 만료 시간 (exp)
                // private claim: 우리가 인증 과정에서 필요한 사적 정보
                .claim("user_id", user.getId())
                .claim("name", user.getName())
                .claim("role", user.getRole().name())
                .claim("token_type", "access")
                .signWith(getSecretKey())
                .compact(); // 최종적으로 모든 정보를 압축하여 JWT 문자열을 생성.
    }

    // Refresh Token 생성
    public String generateRefreshToken(User user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtProperties.getRefreshTokenExpiration());

        return Jwts.builder()
                .header()
                    .type("JWT")
                    .and()
                .issuer(jwtProperties.getIssuer()) // 발급자 (iss)
                .subject(user.getEmail()) // 주체, 사용자 식별자 (sub)
                .issuedAt(now) // 발급 시간 (iat)
                .expiration(expiryDate) // 만료 시간 (exp)
                // private claim: 우리가 인증 과정에서 필요한 사적 정보
                .claim("user_id", user.getId())
                .claim("token_type", "refresh")
                .signWith(getSecretKey())
                .compact(); // 최종적으로 모든 정보를 압축하여 JWT 문자열을 생성.
    }

    // JWT 토큰 검증 및 Claims 반환
    public Claims validateToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSecretKey()) // 문자열로 압축된 JWT를 파싱할 때 서명을 검증
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

        } catch (ExpiredJwtException e) {
            log.warn("만료된 JWT 토큰: {}", e.getMessage());
            throw new BusinessException(ErrorCode.EXPIRED_TOKEN);
        } catch (UnsupportedJwtException e) {
            log.warn("지원되지 않는 JWT 토큰: {}", e.getMessage());
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        } catch (MalformedJwtException e) {
            log.warn("잘못된 JWT 서명: {}", e.getMessage());
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        } catch (SecurityException e) {
            log.warn("JWT 서명 검증 실패: {}", e.getMessage());
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        } catch (IllegalArgumentException e) { // 나중에 커스텀 예외 타입으로 처리하세요.
            throw new BusinessException(ErrorCode.INVALID_TOKEN);
        }
    }

    // 토큰 유효성 검사
    public boolean isTokenValid(String token) {
        try {
            validateToken(token);
            return true;
        } catch (BusinessException e) {
            return false;
        }
    }

    // 토큰에서 사용자 ID 추출
    public Long getUserId(String token) {
        Claims claims = validateToken(token);
        return claims.get("user_id", Long.class);
    }

    // 토큰에서 이메일 추출
    public String getEmail(String token) {
        Claims claims = validateToken(token);
        return claims.getSubject();
    }

    // 토큰에서 역할 추출
    public String getRole(String token) {
        Claims claims = validateToken(token);
        return claims.get("role", String.class);
    }

    // 액세스 토큰 만료시간 조회
    public Long getAccessTokenExpirationInSeconds() {
        return jwtProperties.getAccessTokenExpiration() / 1000;
    }


}
















