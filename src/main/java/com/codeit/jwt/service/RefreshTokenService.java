package com.codeit.jwt.service;

import com.codeit.jwt.config.JwtProperties;
import com.codeit.jwt.domain.token.RefreshToken;
import com.codeit.jwt.repository.RefreshTokenRepository;
import com.codeit.jwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;
    private final JwtProperties jwtProperties;

    /**
     * Refresh Token 저장
     */
    @Transactional
    public void saveRefreshToken(Long userId, String token) {
        // 기존 Refresh Token 삭제 (사용자당 하나만 유지)
        refreshTokenRepository.deleteByUserId(userId);

        // 새 Refresh Token 저장
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .userId(userId)
                .expiresAt(LocalDateTime.now().plusSeconds(
                        jwtProperties.getRefreshTokenExpiration() / 1000
                ))
                .build();

        refreshTokenRepository.save(refreshToken);

        log.debug("Refresh Token 저장: userId={}", userId);
    }


}















