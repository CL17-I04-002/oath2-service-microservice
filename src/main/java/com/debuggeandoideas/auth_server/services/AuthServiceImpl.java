package com.debuggeandoideas.auth_server.services;

import com.debuggeandoideas.auth_server.dtos.TokenDto;
import com.debuggeandoideas.auth_server.dtos.UserDto;
import com.debuggeandoideas.auth_server.entities.UserEntity;
import com.debuggeandoideas.auth_server.helpers.JwtHelper;
import com.debuggeandoideas.auth_server.repositories.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Transactional
@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService{
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtHelper jwtHelper;
    private static final String USER_EXCEPTION_MSG = "Error to auth user";

    @Override
    public TokenDto login(UserDto user) {
        final var userFromDb = userRepository.findByUsername(user.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, USER_EXCEPTION_MSG));
        this.validPassword(user, userFromDb);
        return TokenDto.builder().accesToken(jwtHelper.createToken(userFromDb.getUsername())).build();
    }

    @Override
    public TokenDto validateToken(TokenDto token) {
        if(this.jwtHelper.validateToken(token.getAccesToken())){
            return TokenDto.builder().accesToken(token.getAccesToken()).build();
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, USER_EXCEPTION_MSG);
    }
    private void validPassword(UserDto user, UserEntity userEntity){
        if(!this.passwordEncoder.matches(user.getPassword(), userEntity.getPassword())){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, USER_EXCEPTION_MSG);
        }
    }
}
