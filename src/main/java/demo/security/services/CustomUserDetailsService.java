package demo.security.services;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService{

	
	UserEntityService userentityservice;
	
	public CustomUserDetailsService(UserEntityService userentityservice) {
		super();
		this.userentityservice = userentityservice;
	}


	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.userentityservice.findByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException(username +  " " + "no encontrado"));
	}

	
}
