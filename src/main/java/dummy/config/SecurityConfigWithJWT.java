package dummy.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import dummy.filter.JWTAuthenticationFilter;

/* 
 * NOT RECOMMENDED. Because generating Self-signed JWT then sent it back to the client browser is really very dangerous and prone to vulnerable  with respect to 
 * information security.
 * Reference : https://youtu.be/JdGOb7AxUo0?si=q3HMTU8fEIPo09wj
 * 			https://www.keyfactor.com/blog/self-signed-certificate-risks/
 * Recommended way is to use generating Cookie-based authentication using HTTPOnly.
 * Reference : https://www.google.com.au/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwj8uaOK9PaAAxWcS2wGHW5gCvAQFnoECA0QAw&url=https%3A%2F%2Fresources.infosecinstitute.com%2Ftopics%2Fgeneral-security%2Fsecuring-cookies-httponly-secure-flags%2F%23%3A~%3Atext%3DHttpOnly%2520and%2520secure%2520flags%2520can%2Cis%2520HTTP%2520over%2520SSL%252FTLS.&usg=AOvVaw05_1lfrMEkB8my_0laHyL6&opi=89978449
 * Authorization Servers don't use JWT.
 */

@Configuration
@Import({GsonConfig.class,RedisConfig.class})
@ConditionalOnExpression("${jwt.enabled:true} && ${oauth.enabled:false}")
@EnableWebSecurity
@EnableMethodSecurity
@Order(2)
public class SecurityConfigWithJWT {
	
	RsaKeyProperties jwtConfigProperties;
	
	public SecurityConfigWithJWT(RsaKeyProperties jwtConfigProperties) {
		this.jwtConfigProperties = jwtConfigProperties;
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {  
		return new BCryptPasswordEncoder();

	} 
	
	@Bean
	public SecurityFilterChain jwtsecurityFilterChain(HttpSecurity http)  throws Exception{
		return  http.csrf(csrf -> csrf.disable())
	                .cors(cors -> cors.disable())
	                .authorizeHttpRequests(a ->  a.anyRequest().authenticated())
	                .httpBasic(Customizer.withDefaults())
	                .formLogin(Customizer.withDefaults()) 
	                // enable HTTPS
	                .requiresChannel(channel -> channel.anyRequest().requiresSecure())
	                .formLogin(login -> login.loginProcessingUrl("/auth/loginprocess"))
	                .addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class) // to refesh expired token before checking user is logged in or out
	                .exceptionHandling(exception -> exception.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint()) //  to prepare an authentication attempt that contains a Bearer Token  and supported by JwtAuthenticationProvider.
	                										 .accessDeniedHandler(new BearerTokenAccessDeniedHandler())) 
	                // Disables session as well as prevents form login redirection on every request as we're using JWT
	                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
	                								// disable concurrent session for the same user
							 							  .maximumSessions(1))  
	                // need to manually log out using JWT
	        //        .logout(logout -> logout.logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext()))
	                   // to add HSTS header 
	                .headers(headers -> headers.httpStrictTransportSecurity(hsts -> {
																							hsts.maxAgeInSeconds(31536000).includeSubDomains(true);
																							hsts.requestMatcher(AnyRequestMatcher.INSTANCE);
																						}
								   											   )
								                		   					   .frameOptions(frame -> frame.sameOrigin())
								   											   .xssProtection(xss -> xss.disable())
								   											   .addHeaderWriter(new StaticHeadersWriter("X-Content-Security-Policy","default-src 'self'"))
								   											   .addHeaderWriter(new StaticHeadersWriter("X-WebKit-CSP","default-src 'self'"))
								   											   .addHeaderWriter(new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN))) 
	                .oauth2ResourceServer(oauth2ressrvrconf -> oauth2ressrvrconf.jwt(jwtconf -> jwtconf.decoder(jwtDecoder())
	                																					.jwtAuthenticationConverter(jwtAuthenticationConverter())))
	                .build();
	                
	}
	
	@ConditionalOnProperty(name = "jwt.enabled",havingValue = "true")
	@Bean
	public JwtDecoder jwtDecoder() {
	    return NimbusJwtDecoder.withPublicKey( jwtConfigProperties.getPublicKey()).build();
	} 
	
	@ConditionalOnProperty(name = "jwt.enabled",havingValue = "true")
	@Bean 
	JwtEncoder jwtEncoder() {
		JWK jwk = new RSAKey.Builder(jwtConfigProperties.getPublicKey()).privateKey(jwtConfigProperties.getPrivateKey()).build();
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}
	
    
    /* SCOPE_ is automatically prefixed by using JWT if jwt.enabled is true 
     * Reference : oauth2/oauth2-resource-server/src/main/java/org/springframework/security/oauth2/server/resource/authentication/JwtGrantedAuthoritiesConverter.java
     * to remove SCOPE_ prefix altogether use jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
     */
    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter(){
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");
        Converter<Jwt, AbstractAuthenticationToken> jwtConverter = new JwtAuthenticationConverter(); 
        ((JwtAuthenticationConverter) jwtConverter).setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtConverter;
    }
}
