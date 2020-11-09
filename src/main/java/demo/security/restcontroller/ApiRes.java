package demo.security.restcontroller;

import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import demo.security.model.LoginRequest;
import demo.security.model.UserEntity;
import demo.security.security.jwt.JwtTokenProvider;
import demo.security.services.UserEntityService;

@RestController
@RequestMapping("/api")
public class ApiRes {

	@Autowired
	private UserEntityService userEntityService;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
//Optional<UserEntity>
	@RequestMapping(value = "/me/", method = RequestMethod.GET) 
	public String Prueba(@AuthenticationPrincipal UserEntity user) {
		return "test";
//		return "Test";
	}
	
	
	@PostMapping("/auth/login/")
	public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest){
		System.out.println("paao");
			Authentication authentication = authenticationManager
														.authenticate(new UsernamePasswordAuthenticationToken(
																loginRequest.getUserName(),
																loginRequest.getPassword()
																));
			
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			UserEntity user = (UserEntity) authentication.getPrincipal();
			
			String jwtToken = jwtTokenProvider.generateToken(authentication);
			
			return ResponseEntity.status(HttpStatus.ACCEPTED)
					.body(jwtToken);
			
	}
	
	
	@RequestMapping(value="/logout", method = RequestMethod.GET)
	public String logoutPage (HttpServletRequest request, HttpServletResponse response) {
	    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	    if (auth != null){    
	        new SecurityContextLogoutHandler().logout(request, response, auth);
	    }
//	    return "redirect:/login?logout";//You can redirect wherever you want, but generally it's a good practice to show login screen again.
	    return "logout";
	}	
	
	
}
