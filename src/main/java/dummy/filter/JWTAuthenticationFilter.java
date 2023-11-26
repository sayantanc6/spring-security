package dummy.filter;

import java.io.IOException;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import dummy.repository.ProductUserRepository;
import dummy.repository.TokenRepository;
import dummy.security.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@ConditionalOnProperty(havingValue = "jwt.enabled",value = "true")
public class JWTAuthenticationFilter extends OncePerRequestFilter { 
	 
 //	@Autowired //  Autowiring inside filter is discouraged..
	JWTService jwtService;
	 
	ProductUserRepository produsrrepo;
	
	TokenRepository tokenrepo;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		
		// ..but we can lazy set it on the first call
		ServletContext servletContext = request.getServletContext();
        WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(servletContext);
        jwtService = webApplicationContext.getBean(JWTService.class);
        produsrrepo = webApplicationContext.getBean(ProductUserRepository.class);
        tokenrepo = webApplicationContext.getBean(TokenRepository.class);
        
		String bearerToken = request.getHeader("Authorization");
		if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            bearerToken = bearerToken.substring(7, bearerToken.length()); 
    		String username = jwtService.getUsernameByToken(bearerToken);
    		
    		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    		
    		if (!authentication.isAuthenticated()) { // not logged in or already logged out
				bearerToken=null;
			}else if (!tokenrepo.existsById(username)) { // logged in but token expired
	    		if (produsrrepo.existsByUsername(username) && !jwtService.isTokenValid(bearerToken)) {
	    			request.setAttribute("refreshtoken", bearerToken); 
	    			response.sendRedirect(request.getContextPath()+"/auth/refreshtoken");
	    		}
			}
        }
		filterChain.doFilter(request, response);
	}
}
