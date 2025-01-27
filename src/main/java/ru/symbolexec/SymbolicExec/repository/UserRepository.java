package ru.symbolexec.SymbolicExec.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.symbolexec.SymbolicExec.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
