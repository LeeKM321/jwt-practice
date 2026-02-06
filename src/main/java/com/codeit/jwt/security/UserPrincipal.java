package com.codeit.jwt.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Getter
@RequiredArgsConstructor
public class UserPrincipal implements UserDetails {

    private final Long id;
    private final String email;
    private final String name;
    private final Collection<? extends GrantedAuthority> authorities;

    // JWT Claims로부터 UserPrincipal 생성
    // 정적 팩토리 메서드 이름을 지으실 때
    // from: 하나의 객체 매개변수를 받아서 특정 타입으로 변환할 때 사용
    // of: 여러 개의 매개변수를 받아서 적절한 객체를 생성할 때 사용
    public static UserPrincipal of(Long id, String email, String name, String role) {
        Collection<GrantedAuthority> authorities
                = Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role));

        return new UserPrincipal(id, email, name, authorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return null; // JWT 방식에서는 비밀번호 사용 x
    }

    @Override
    public String getUsername() {
        return email;
    }

}
