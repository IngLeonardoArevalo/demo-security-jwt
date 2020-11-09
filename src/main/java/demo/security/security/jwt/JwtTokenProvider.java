package demo.security.security.jwt;

import java.util.Date;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import demo.security.model.UserEntity;
import demo.security.model.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
/*
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
*/
@Component
public class JwtTokenProvider {
	
		public static final String TOKEN_HEADER = "Authorization";
		public static final String TOKEN_PREFIX = "Bearer ";
		public static final String TOKEN_TYPE = "JWT";
		
//		@Value("${jwt.secret:Password1}")
		private final String jwtSecreto = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
				+ "35usWj9X8HwGS-CDcx1JP2NmqcrLwZ4EKp8sNThf3cY";
		
	//	@Value("$(jwt.token-expiration:864000)")
		private final int jwtDurationTokenenSegundos = 864000;
		
		public String generateToken(Authentication authentication)
		{
			UserEntity user = (UserEntity) authentication.getPrincipal(); //extraemops el user entity
			
			Date tokenExpirationDate = new Date(System.currentTimeMillis() + (jwtDurationTokenenSegundos * 1000));

			
			return Jwts.builder()
					.signWith(Keys.hmacShaKeyFor(jwtSecreto.getBytes()) , SignatureAlgorithm.HS512)
					.setHeaderParam("typ", TOKEN_TYPE)
//					.setSubject(Long.toString(user.getId()))
					.setSubject("leonardo")
					.setIssuedAt(new Date())
					.setExpiration(tokenExpirationDate)
					.claim("fullname", user.getUsername())
					.claim("roles", 
							user.getRoles().stream()
								.map(UserRole::name)
								.collect(Collectors.joining(", "))
							)
					.compact();
					
		}
		
		
		public Long getUserIdFromJWT(String jwtString)
		{
			
			Claims claims = Jwts.parser()
								.setSigningKey(Keys.hmacShaKeyFor(jwtSecreto.getBytes()))
								.parseClaimsJws(jwtString)
								.getBody();
			
			return Long.parseLong(claims.getSubject());
		}
		

		public boolean validateToken(String authToken) {
			try {
				Jwts.parser().setSigningKey(jwtSecreto.getBytes()).parseClaimsJws(authToken);
				return true;
			} catch (SignatureException e) {
				// TODO: handle exception
			}catch (MalformedJwtException e) {
				// TODO: handle exception
			}catch (ExpiredJwtException e) {
				// TODO: handle exception
			}catch (UnsupportedJwtException e) {
				// TODO: handle exception
			}

			return false;

		}
		

}
