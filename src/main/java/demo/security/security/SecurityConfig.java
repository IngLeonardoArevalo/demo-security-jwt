package demo.security.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import demo.security.security.jwt.JwtAuthorizacionFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	//@Autowired
	//public CustomBasicAuthenticationEntryPoint customBasicAuthenticationEntryPoint;
	
	
	@Autowired
	public UserDetailsService userDetailsService;
	
	@Autowired
	public PasswordEncoder passwordEncoder;
	
	@Autowired
	public AuthenticationEntryPoint jwtAuthenticationEntryPoint;
	
	@Autowired
	public JwtAuthorizacionFilter jwtAuthorizacionFilter;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
			http
			.csrf()
			.disable()
			.exceptionHandling()
				.authenticationEntryPoint(jwtAuthenticationEntryPoint)
			.and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeRequests()
				.antMatchers(HttpMethod.POST, "/api/", "/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.POST, "/api/auth/login/", "/**").permitAll()
				.antMatchers(HttpMethod.GET, "/api/me/", "/**").hasRole("ADMIN")
				.antMatchers(HttpMethod.GET, "/logout/", "/**").permitAll()
				.anyRequest().authenticated();
			
			//añadimos filtro -sera encargado de recoger el token
			http.addFilterBefore(jwtAuthorizacionFilter, UsernamePasswordAuthenticationFilter.class);
	}




	
	
	

}
