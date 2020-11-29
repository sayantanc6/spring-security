package dummy.config;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.WebApplicationContext;

import dummy.security.CustomAuthenticationFailureHandler;
import dummy.security.MyLogoutSuccessHandler;
import dummy.security.MyUserDetailsService;
import dummy.security.OAuth2AuthenticationFailureHandler;
import dummy.security.OAuth2AuthenticationSuccessHandler;
import dummy.security.SecurityHandler;

@Configuration
@PropertySource("application.properties")
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter { 
	
	@Autowired
    private WebApplicationContext applicationContext;
	
	@Autowired
    private MyUserDetailsService userDetailsService;
	
    @Autowired
    SecurityHandler handler;
    
    @Autowired
	public DataSource dataSource;
    
	@PostConstruct
    public void completeSetup() {
        userDetailsService = applicationContext.getBean(MyUserDetailsService.class);
    }
	
	@Bean(BeanIds.AUTHENTICATION_MANAGER) 
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService)
        .passwordEncoder(encoder())
        .and()
        .authenticationProvider(authenticationProvider())
        .jdbcAuthentication()
        .dataSource(dataSource)
        .usersByUsernameQuery("select u.email,u.password,u.enabled "
                + "from USER u "
                + "where u.email = ?");
		
		auth.inMemoryAuthentication()
        .withUser("user1").password("{noop}user1Pass").roles("USER")
        .and()
        .withUser("admin1").password("{noop}admin1Pass").roles("ADMIN")
        .and()
        .withUser("guest1").password("{noop}guest1Pass").roles("GUEST");
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring()
        .antMatchers("/resources/**");
	}
	
    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(); 
    }
	
	@Bean
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }
	
	@Bean
    public DaoAuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(encoder());
        return authProvider;
    }

	@Configuration 
    @Order(1)
    public static class BasicAuthConfigurationAdapter extends SpringSecurityConfig {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
        	
            http.antMatcher("/admin/**")
                .authorizeRequests().anyRequest().hasRole("ADMIN")
                .and().httpBasic().authenticationEntryPoint(authenticationEntryPoint())    
                .and().exceptionHandling().accessDeniedPage("/403");
        }
        
        @Bean
        public AuthenticationEntryPoint authenticationEntryPoint(){
            BasicAuthenticationEntryPoint entryPoint = new  BasicAuthenticationEntryPoint();
            entryPoint.setRealmName("admin realm");
            return entryPoint;
        }
    }
	
	@Configuration
	@Order(2)
    public static class FormLoginConfigurationAdapter extends SpringSecurityConfig {
		
		@Autowired
	     MyLogoutSuccessHandler logoutSuccessHandler;
		
		@Autowired
	     CustomAuthenticationFailureHandler authenticationFailureHandler;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().antMatchers("/login", "/").hasRole("USER")
			.and()
			 .formLogin().loginPage("/login.html").loginProcessingUrl("/login").defaultSuccessUrl("/homepage.html", true)
		     .successHandler(this.handler).permitAll().failureHandler(authenticationFailureHandler).failureUrl("/login.html?error=true")
		     .and()
		     .logout().logoutSuccessUrl("/afterlogout.html").logoutSuccessHandler(logoutSuccessHandler).deleteCookies("JSESSIONID")
		     .and()
		     .exceptionHandling().defaultAuthenticationEntryPointFor(loginUrlauthenticationEntryPointWithWarning(),  new AntPathRequestMatcher("/user/private/**"))
	            .defaultAuthenticationEntryPointFor(loginUrlauthenticationEntryPoint(), new AntPathRequestMatcher("/user/general/**"))
	            .accessDeniedPage("/403")
	            .and()
		        .rememberMe().rememberMeParameter("remember-me-new").key("uniqueAndSecret").tokenValiditySeconds(86400)
		        .and()
		        .sessionManagement().sessionFixation().migrateSession().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).invalidSessionUrl("/invalidSession.html")
		        .maximumSessions(2).expiredUrl("/sessionExpired.html");
		}
	    
		@Bean
        public AuthenticationEntryPoint loginUrlauthenticationEntryPoint(){
            return new LoginUrlAuthenticationEntryPoint("/userLogin");
        }
        
        @Bean
        public AuthenticationEntryPoint loginUrlauthenticationEntryPointWithWarning(){
            return new LoginUrlAuthenticationEntryPoint("/userLoginWithWarning");
        }
	}
	
	
	@Configuration
	@Order(3)
    public static class OauthLoginConfigurationAdapter extends SpringSecurityConfig{
		
	    @Autowired
		MyUserDetailsService customOauth2userDetailsService;
	    
	    @Autowired
		OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
		
		@Autowired
		OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().antMatchers("/home", "/login**","/callback/", "/webjars/**", "/error**", "/oauth2/authorization/**")
            .permitAll() 
	        .anyRequest().authenticated()
	        .and()
	        .oauth2Login().redirectionEndpoint().baseUri("/oauth2/callback/*").and().userInfoEndpoint()
	        .and().authorizationEndpoint().baseUri("/oauth2/authorize-client").authorizationRequestRepository(authorizationRequestRepository())
			.and()
			.tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient()).and()
			.defaultSuccessUrl("/loginSuccess")
	        .failureUrl("/loginFailure");
		}
		
		@Bean
	    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
	        return new HttpSessionOAuth2AuthorizationRequestRepository();
	    }
		
		@Bean
	    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
	        DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
	        return accessTokenResponseClient;
	    }
	}
 }