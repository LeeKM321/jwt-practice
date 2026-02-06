package com.codeit.jwt.security;

import com.codeit.jwt.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            String jwt = extractJwtFromRequest(request);
            if (jwt != null && jwtUtil.isTokenValid(jwt)) {
                authenticateUser(jwt, request);
            }
        } catch (Exception e) {
            log.error("JWT 인증 실패: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    // JWT에서 사용자 정보를 추출하고 SecurityContext에 설정
    private void authenticateUser(String jwt, HttpServletRequest request) {
        Claims claims = jwtUtil.validateToken(jwt);

        Long userId = claims.get("user_id", Long.class);
        String email = claims.getSubject();
        String name = claims.get("name", String.class);
        String role = claims.get("role", String.class);

        UserPrincipal principal = UserPrincipal.of(userId, email, name, role);

        // Spring Security의 인증 객체 생성
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                principal, // 컨트롤러 등에서 활용할 유저 정보
                null, // 인증된 사용자의 비밀번호: 보통 null 혹은 빈 문자열
                principal.getAuthorities() // 권한 목록
        );

        // 부가 정보 설정 (선택 사항)
        // 현재 HTTP 요청(request)에서 사용자의 IP 주소나 기타 요청에 관련된 정보를 추출해서 인증 객체에 Detail로 추가
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        // Security 컨텍스트에 인증 정보 저장 (이 코드가 실행 되어야 스프링은 해당 요청이 끝날 때까지 이 사용자를 '로그인 된 사용자' 로 인식)
        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.info("JWT 인증 성공: user_id={}, email={}, role={}", userId, email, role);
    }

    // Authorization 헤더에서 JWT 토큰 추출
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Bearer 떼고 토큰의 값만 리턴
        }

        return null;
    }

}












