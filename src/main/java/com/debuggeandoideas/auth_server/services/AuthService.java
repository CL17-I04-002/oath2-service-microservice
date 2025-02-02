package com.debuggeandoideas.auth_server.services;

import com.debuggeandoideas.auth_server.dtos.TokenDto;
import com.debuggeandoideas.auth_server.dtos.UserDto;

public interface AuthService {
    TokenDto login(UserDto user);
    TokenDto validateToken(TokenDto token);
}
