package dummy.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,Authentication authentication) throws IOException, ServletException {
		String redirect_url = WebUtils.getCookie(request, "redirect_uri").getValue(); 

		if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + redirect_url);
            return;
        }
		
		super.clearAuthenticationAttributes(request); 
        getRedirectStrategy().sendRedirect(request, response, redirect_url);  
	}
}
