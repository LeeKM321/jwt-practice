package com.codeit.jwt.dto.common.ApiResponse;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

/**
 * 공통 API 응답 포맷
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL) // 응답 데이터 중 값이 null인 필드는 JSON 결과물에 포함시키지 않겠다.
public record ApiResponse<T>(
        boolean success,
        T data,
        String message,
        ErrorDetails error
) {

    /**
     * 성공 응답 (데이터 있음)
     */
    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .data(data)
                .build();
    }

    /**
     * 성공 응답 (메시지만)
     */
    public static <T> ApiResponse<T> success(String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .build();
    }

    /**
     * 실패 응답
     */
    public static <T> ApiResponse<T> error(String message, String details) {
        return ApiResponse.<T>builder()
                .success(false)
                .error(new ErrorDetails(message, details))
                .build();
    }

    /**
     * 에러 상세 정보
     */
    public record ErrorDetails(
            String message,
            String details
    ) {
    }
}
