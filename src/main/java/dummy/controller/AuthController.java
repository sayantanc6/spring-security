package dummy.controller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;

import dummy.entity.ProductUser;
import dummy.model.ProductUserModel;
import dummy.model.Token;
import dummy.repository.ProductUserRepository;
import dummy.repository.TokenRepository;
import dummy.security.JWTService;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/auth")
@PreAuthorize("permitAll()") 
@ConditionalOnProperty(name = "oauth.enabled",havingValue = "false")
public class AuthController {
	
	@Autowired
	ProductUserRepository produserrepo;
	
	@Autowired
	PasswordEncoder passwordEncoder; 
	
	@Autowired
	Gson gson; 
	
	@Autowired
	ProductUserModel usermodel;
	
	@Autowired
	ApplicationContext appContext; 
	 
	@Value("#{new Boolean('${jwt.enabled}')}")
	Boolean jwtEnabled;
	
	@Autowired
	JWTService jwtService;
	
	@Autowired
	TokenRepository tokenrepo;
	
	@PreAuthorize("isAnonymous()")
	@PostMapping(value = "/register",produces = MediaType.APPLICATION_JSON_VALUE,
			headers = "Accept=application/json",consumes = MediaType.APPLICATION_JSON_VALUE)
	public String register(@RequestBody ProductUserModel user) {
		
		if (produserrepo.existsByUsername(user.getUsername())) {  
			return user.getUsername() + " already taken";
		}else { 
			System.out.println(user.toString());
				user.setPassword(passwordEncoder.encode(user.getPassword()));  
				produserrepo.save(gson.fromJson(gson.toJson(user), ProductUser.class));
				return user.getUsername() + " succesfully registered";
		}
	}  
	
	@GetMapping(value = "/loginprocess",produces = MediaType.APPLICATION_JSON_VALUE,
			headers = "Accept=application/json",consumes = MediaType.APPLICATION_JSON_VALUE)
	public String login(@AuthenticationPrincipal ProductUser produser) {
		
		String username = produser.getUsername();
		String message = null; 
		
			if (produserrepo.existsByUsername(username) && !jwtEnabled)
				message = username + " logged in succesfully";
			else if (produserrepo.existsByUsername(username) && jwtEnabled) {
					message = jwtService.generateToken(produser);

				tokenrepo.save(new Token(username,message)); 
			} else {
				message = username + "not found";

			} 
		return message;
	} 
	 
	@GetMapping(value = "/refreshtoken",produces = MediaType.APPLICATION_JSON_VALUE,
			headers = "Accept=application/json",consumes = MediaType.APPLICATION_JSON_VALUE)
	public String refreshtoken(@RequestParam("refreshtoken")String oldtoken) {
		
				String username = jwtService.getUsernameByToken(oldtoken);
				String newToken = jwtService.generateToken(produserrepo.findByUsername(username).get());
				tokenrepo.save(new Token(username,newToken));
				return "token refreshed : "+newToken;  
	}
	
	@PreAuthorize("isFullyAuthenticated()") 
	@GetMapping(value = "/logout",produces = MediaType.APPLICATION_JSON_VALUE,
	headers = "Accept=application/json",consumes = MediaType.APPLICATION_JSON_VALUE)
	public void logout(Principal principal,HttpServletRequest request) { 
		String username = principal.getName();
		try {
			if (tokenrepo.existsById(username)) {
				tokenrepo.deleteById(username);
				SecurityContextHolder.clearContext();
				request.logout();
			}
		} catch (Exception e) {
			System.out.println(username+" id doesn't exist");
		}
		System.out.println(username+" logged out ");
	}
} 
