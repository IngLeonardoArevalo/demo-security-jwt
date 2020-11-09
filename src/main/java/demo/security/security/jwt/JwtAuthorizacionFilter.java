package demo.security.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import demo.security.model.UserEntity;
import demo.security.services.CustomUserDetailsService;

@Component
public class JwtAuthorizacionFilter extends OncePerRequestFilter{
	
	@Autowired
	public JwtTokenProvider jwtTokenProvider;
	
	@Autowired
	public CustomUserDetailsService customUserDetailsService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		
			try {
				String token = getJwtFromRequest(request);

				
				if (StringUtils.hasText(token) && (jwtTokenProvider.validateToken(token))) {

					//Long userID = jwtTokenProvider.getUserIdFromJWT(token); //buscar user
					
					UserEntity user = (UserEntity) customUserDetailsService.loadUserByUsername("leonardo");

					
					UsernamePasswordAuthenticationToken authentication = 
								new UsernamePasswordAuthenticationToken(user, user.getRoles(), user.getAuthorities());
				
					authentication.setDetails(new WebAuthenticationDetails(request));
					
					//se guarda el contextp de seguridad
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
				
			} catch (Exception e) {
				System.out.println(e.getMessage());
			}
			
			filterChain.doFilter(request, response);
	}

	private String getJwtFromRequest(HttpServletRequest request) {
		String bearerToken = request.getHeader(jwtTokenProvider.TOKEN_HEADER);
		if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtTokenProvider.TOKEN_PREFIX))
		{
			return bearerToken.substring(jwtTokenProvider.TOKEN_PREFIX.length(), bearerToken.length());
		}
		
		return null;
	}

}
