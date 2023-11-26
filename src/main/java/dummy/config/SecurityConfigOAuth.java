package dummy.config;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
 
/*As keycloak is responsible for Identity And Access Management 3rd party provider,
 * first we need to configure..
 * users,groups,roles and privileges,
 * authentication and authorisation,
 * registration,
 * user federation for database and many more..
 * next get an access token using token endpoint..
 * curl --location 'http://localhost:8080/realms/Spring_Security_realm1/protocol/openid-connect/token' \
 *		--header 'Content-Type: application/x-www-form-urlencoded' \
 *		--data-urlencode 'grant_type=password' \
 *		--data-urlencode 'client_id=spring_security_webapp' \
 *		--data-urlencode 'username=sayantanuser' \
 *		--data-urlencode 'password=abcuser' \
 *		--data-urlencode 'client_secret=LWCnvEvdjHGgqvbCbjeTXgllO2lHeqtD'
 * finally we need to integrate with Spring Boot Application.
 * */
 
@Configuration
@ConditionalOnExpression("${jwt.enabled:false} && ${oauth.enabled:true}")
@Import(GsonConfig.class)
@EnableMethodSecurity
public class SecurityConfigOAuth {

	@Bean
	public SecurityFilterChain oauthsecurityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf(csrf -> csrf.disable())  
                .cors(cors -> cors.disable())
                .anonymous(anonymous -> anonymous.disable()) 
                .authorizeHttpRequests(a ->  {  
        	 							a.requestMatchers("/auth/**").permitAll();
        	 							a.anyRequest().authenticated(); 
            	 						})
                 // enable HTTPS
                 .requiresChannel(channel -> channel.anyRequest().requiresSecure())
                // disable concurrent session for the same user
                .sessionManagement(session -> session.maximumSessions(1))
                .oauth2ResourceServer(oauth2Configurer -> oauth2Configurer.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwt -> {
                    Map<String, Collection<String>> realmAccess = jwt.getClaim("realm_access");
                    Collection<String> roles = realmAccess.get("roles");
                    var grantedAuthorities = roles.stream()
                            .map(role -> new SimpleGrantedAuthority(role))
                            .collect(Collectors.toList());
                    return new JwtAuthenticationToken(jwt, grantedAuthorities);
                })))
                .build(); 
                
        }
}
