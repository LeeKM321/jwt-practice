package com.codeit.jwt.service;

import com.codeit.jwt.domain.user.User;
import com.codeit.jwt.domain.user.UserRole;
import com.codeit.jwt.dto.auth.LoginRequest;
import com.codeit.jwt.dto.auth.LoginResponse;
import com.codeit.jwt.dto.auth.SignupRequest;
import com.codeit.jwt.exception.BusinessException;
import com.codeit.jwt.exception.ErrorCode;
import com.codeit.jwt.repository.UserRepository;
import com.codeit.jwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    /**
     * 회원가입
     */
    @Transactional
    public void signup(SignupRequest request) {
        // 이메일 중복 확인
        if (userRepository.existsByEmail(request.email())) {
            throw new BusinessException(ErrorCode.DUPLICATE_EMAIL);
        }

        // 사용자 생성
        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .name(request.name())
                .role(UserRole.USER)
                .build();

        userRepository.save(user);

        log.info("회원가입 완료: email={}", request.email());
    }

    /**
     * 로그인
     * 세션/쿠키 기반 인증 방식은 로그인 로직을 따로 구현하지 않았습니다만, JWT는
     * 토큰 발급에 대한 통제권을 개발자에게 주기 때문에 우리가 직접 로그인 로직을 구현합니다.
     */
    public LoginResponse login(LoginRequest request) {
        // 사용자 조회
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BusinessException(ErrorCode.INVALID_CREDENTIALS));

        // 비밀번호 확인 (암호화)
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BusinessException(ErrorCode.INVALID_CREDENTIALS);
        }

        // JWT 생성
        String accessToken = jwtUtil.generateAccessToken(user); // 15분
        String refreshToken = jwtUtil.generateRefreshToken(user); // 2주

        // Refresh Token 저장 (DB, Redis)
        refreshTokenService.saveRefreshToken(user.getId(), refreshToken);

        log.info("로그인 성공: email={}", request.email());

        return LoginResponse.of(
                accessToken,
                refreshToken,
                jwtUtil.getAccessTokenExpirationInSeconds()
        );
    }



}
















