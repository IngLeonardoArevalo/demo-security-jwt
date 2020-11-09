package demo.security.repo;

import java.util.Optional;

//import org.springframework.data.jpa.repository.JpaRepository;

import demo.security.model.UserEntity;

public interface UserEntityRepository //extends JpaRepository<UserEntity, Long>
{
	
		Optional<UserEntity> findByUsername(String username);

}
