package com.codeit.jwt.dto.user;

import com.codeit.jwt.domain.user.User;
import com.codeit.jwt.domain.user.UserRole;
import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.LocalDateTime;

public record UserResponse(
        Long id,
        String email,
        String name,
        UserRole role,

        @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
        LocalDateTime createdAt
) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getName(), user.getRole(), user.getCreatedAt());
    }

}
