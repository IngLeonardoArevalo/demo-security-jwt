package demo.security.services;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import demo.security.model.UserEntity;
import demo.security.model.UserRole;
import demo.security.repo.UserEntityRepository;

@Service
public class UserEntityService {

	//@Autowired
	//UserEntityRepository repo;
	
	private final PasswordEncoder passwordEncoder;
	
	public UserEntityService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}



	public Optional<UserEntity> findByUsername(String username){
		
		UserEntity user = new UserEntity();
		user.setUsername(username);
		user.setPassword(passwordEncoder.encode("123456"));
		user.setAvatar("avatar");
		Set<UserRole> ur = new HashSet<UserRole>();
		ur.add(UserRole.ADMIN);
		user.setRoles(ur);
		
		Optional<UserEntity> op = Optional.of(user);
		
		return op;
	}
	
	
	public UserEntity nuevoUsuario(UserEntity userEntity)
	{
		
		UserEntity usent = new UserEntity();
		usent.setPassword(passwordEncoder.encode(userEntity.getPassword()));
		usent.setRoles(Stream.of(UserRole.ADMIN).collect(Collectors.toSet()));
		usent.setUsername(userEntity.getUsername());
		usent.setAvatar("leo");
		
		return usent;
	}
	
		

}
