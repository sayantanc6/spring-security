package dummy.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import dummy.repository.ProductUserRepository;

@Configuration
@Import(GsonConfig.class)
@ConditionalOnExpression("${jwt.enabled:false} && ${oauth.enabled:false}")
@EnableWebSecurity
@EnableMethodSecurity
@Order(1)
public class SecurityConfigWithoutJWT {
	
	@Autowired
	ProductUserRepository productuserrepo;
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		 return  http
				 //	.csrf(csrf -> csrf.disable()) // Never disable CSRF protection while leaving session management enabled! Doing so will open you up to a Cross-Site Request Forgery attack.
                    .cors(cors -> cors.disable())
                    .authorizeHttpRequests(a ->  {
											// Specify that login and register service may be called by anyone.
            	 							a.requestMatchers("/auth/**").permitAll();
            	 							// Specify that any other requests are authenticated.
            	 							a.anyRequest().authenticated();
                	 						})  
	                // enable HTTPS
	                .requiresChannel(channel -> channel.anyRequest().requiresSecure())
                    .exceptionHandling(exception -> exception.accessDeniedHandler(new AccessDeniedHandlerImpl()))
              //     .formLogin(Customizer.withDefaults())
               /*    .formLogin(login -> {
                                login.loginProcessingUrl("/auth/loginprocess")
                                     .failureForwardUrl("/loginfailure") 
                                     .permitAll();
                   }) */
                    // as we are using basic authentication so form login won't be needed
                   .httpBasic(Customizer.withDefaults())
                   //as we are using HTTP BASIC authentication mechanism which is stateless,so you need to store the authentication in the session across requests
              //     .httpBasic(basic -> basic.securityContextRepository(new HttpSessionSecurityContextRepository()))
              //     .requestCache(cache -> cache.requestCache(requestCache)) 
                   .logout(logout ->
                       //     logout.logoutUrl("/logout")
                         //   	  .logoutSuccessUrl("/successlogout")
                            	// Clearing Session Cookies on Logout but in my case not needed
                            //	  .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(CACHE, COOKIES, STORAGE))); 
                                  
                                   // authentication nullified,session invalidated
                                  logout.logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext()))
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
                   
                   // Enables session that prevents form login redirection on every request
                   .requestCache(cache -> cache.requestCache(RequestCache())) 
                   .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
        		   										// disable concurrent session for the same user
                		   								 .maximumSessions(1))
                   .authenticationManager(authManager()) 
                   // explicitly save the SecurityContext to to persist between requests
       			   .securityContext(context -> context.requireExplicitSave(true)) 
                   .build();
 
	}

	@Bean
	HttpSessionRequestCache RequestCache() {
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setCreateSessionAllowed(true);
		return requestCache;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {  
		return new BCryptPasswordEncoder();
	}
	
	 
    @Bean(name = "authManager")
    public AuthenticationManager authManager(){
        DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
        daoProvider.setUserDetailsService(userDetailsService());
        daoProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(daoProvider);
    } 
    

	
	@Bean
	public UserDetailsService userDetailsService() {
	    return username -> productuserrepo.findByUsername(username)
	        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
	} 
}
