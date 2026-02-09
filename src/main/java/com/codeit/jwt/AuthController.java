package com.codeit.jwt;

import com.codeit.jwt.dto.auth.LoginRequest;
import com.codeit.jwt.dto.auth.LoginResponse;
import com.codeit.jwt.dto.auth.RefreshTokenRequest;
import com.codeit.jwt.dto.auth.SignupRequest;
import com.codeit.jwt.dto.common.ApiResponse.ApiResponse;
import com.codeit.jwt.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * 회원가입
     */
    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signup(@Valid @RequestBody SignupRequest request) {
        authService.signup(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success("회원가입이 완료되었습니다."));
    }

    /**
     * 로그인
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Access Token 갱신
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        LoginResponse response = authService.refreshAccessToken(request.refreshToken());
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * 로그아웃
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @Valid @RequestBody RefreshTokenRequest request
    ) {
        authService.logout(request.refreshToken());
        return ResponseEntity.ok(ApiResponse.success("로그아웃되었습니다."));
    }


}
