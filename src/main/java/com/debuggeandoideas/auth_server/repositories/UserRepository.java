package com.debuggeandoideas.auth_server.repositories;

import com.debuggeandoideas.auth_server.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
}
