package dummy.controller;

import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.validation.Valid;

import org.dozer.DozerBeanMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import dummy.entity.Role;
import dummy.entity.User;
import dummy.exception.BadRequestException;
import dummy.model.UserEmployeeModel;
import dummy.repo.UserRepository;

@RestController
@SuppressWarnings("deprecation") 
public class LoginController {
	

    Map<String, String> oauth2AuthenticationUrls = new HashMap<>();

	 private static final String authorizationRequestBaseUri = "oauth2/authorize-client";
	 
	    @Autowired
	    private ClientRegistrationRepository clientRegistrationRepository;
	    
	    @Autowired
	    private OAuth2AuthorizedClientService authorizedClientService; 
	    
	    @Autowired
		DozerBeanMapper mapper; 
	    
	    @Autowired
	    UserRepository repo;

	    @GetMapping("/oauth_login")
	    public String  getLoginPage(Model model) {
	        Iterable<ClientRegistration> clientRegistrations = null;
	        ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
	        if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) { 
	            clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
	        }
	        

	        clientRegistrations.forEach(registration -> oauth2AuthenticationUrls.put(registration.getClientName(), authorizationRequestBaseUri + "/" + registration.getRegistrationId()));
	        model.addAttribute("urls", oauth2AuthenticationUrls);
 
	        return "oauth_login"; 
	    }
	    
	    @GetMapping("/loginSuccess")
	    public String getLoginInfo(Model model, OAuth2AuthenticationToken authentication) {

	        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(), authentication.getName());

	        String userInfoEndpointUri = client.getClientRegistration()
	            .getProviderDetails()
	            .getUserInfoEndpoint()
	            .getUri();

	        if (!StringUtils.isEmpty(userInfoEndpointUri)) {
	            RestTemplate restTemplate = new RestTemplate();
	            HttpHeaders headers = new HttpHeaders();
	            headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + client.getAccessToken()
	                .getTokenValue());

	            HttpEntity<String> entity = new HttpEntity<String>("", headers);

	            ResponseEntity<Map> response = restTemplate.exchange(userInfoEndpointUri, HttpMethod.GET, entity, Map.class);
	            Map userAttributes = response.getBody();
	            model.addAttribute("name", userAttributes.get("name"));
	        }

	        return "loginSuccess"; 
	    }
	    
	    @PostMapping(value = "/signup")
	    public User registerUser(@Valid @RequestBody UserEmployeeModel model) throws BadRequestException{
	    	System.out.println(model);
	        if(repo.existsByEmail(model.getEmail())) {  
	            throw new BadRequestException("Email address already in use.");
	        }

	   //     model.setPassword(passwordEncoder.encode(model.getPassword()));  
	        // Creating user's account
	        User result = repo.save(mapper.map(model, User.class)); 
	        
	        URI location = ServletUriComponentsBuilder
	                .fromCurrentContextPath().path("/user/me")
	                .buildAndExpand(result.getId()).toUri();
	        
	        System.out.println(location);
	        return result;
	    } 
	    
	    @ResponseStatus(code = HttpStatus.BAD_REQUEST)
		@ExceptionHandler(MethodArgumentNotValidException.class)
		public Map<String, String> addCustExceptions(MethodArgumentNotValidException ex){
			Map<String, String> errors = new HashMap<>();
	        ex.getBindingResult().getAllErrors().forEach((error) -> {
	            String fieldName = ((FieldError) error).getField();
	            String errorMessage = error.getDefaultMessage();
	            errors.put(fieldName, errorMessage);
	        });
	        return errors;
		}
}
