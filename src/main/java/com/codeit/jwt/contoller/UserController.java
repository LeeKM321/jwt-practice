package com.codeit.jwt.contoller;

import com.codeit.jwt.dto.common.ApiResponse.ApiResponse;
import com.codeit.jwt.dto.user.UserResponse;
import com.codeit.jwt.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(
            @AuthenticationPrincipal UserPrincipal principal
            ) {
        UserResponse userResponse = new UserResponse(
                principal.getId(),
                principal.getEmail(),
                principal.getName(),
                null,
                null
        );

        return ResponseEntity.ok(ApiResponse.success(userResponse));
    }

}













