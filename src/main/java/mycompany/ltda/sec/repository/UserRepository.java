package mycompany.ltda.sec.repository;

import mycompany.ltda.sec.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Long> {
    public User findByLogin(String login);
}
