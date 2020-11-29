package dummy.security;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import dummy.entity.Privilege;
import dummy.entity.Role;
import dummy.entity.User;
import dummy.model.UserEmployeeModel;
import dummy.repo.UserRepository;

@Service
public class MyUserDetailsService extends DefaultOAuth2UserService  implements UserDetailsService {
	
	Set<GrantedAuthority> authorities;
	
	@Autowired
	UserRepository userrepo;
	
	User user;
	
	@Autowired 
	UserEmployeeModel usermodel;
	
	@Autowired
	MyEmployeePrincipal principal;

	@Override 
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuthuser = super.loadUser(userRequest);
		Map<String, Object> attributes = oAuthuser.getAttributes();
		authorities = new HashSet<>(oAuthuser.getAuthorities());
		
		for (String role : usermodel.getRoles())  
			authorities.add(new SimpleGrantedAuthority(role.toString()));
		
		String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
		
		return new DefaultOAuth2User(authorities, attributes, userNameAttributeName);
	}

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		
        user = userrepo.findByEmail(email);
        if (user == null) 
			return new org.springframework.security.core.userdetails.User(" "," ", true, true, true, true, authorities);
		
		  return new org.springframework.security.core.userdetails.User(email,user.getPassword(), principal.isEnabled(), principal.isAccountNonExpired(), principal.isCredentialsNonExpired(), principal.isAccountNonLocked(), authorities);

	} 
	
	public Collection<? extends GrantedAuthority> getAuthorities(Collection<Role> roles){
		authorities.clear();
		for (Role role : roles) {
			for (Privilege privilege : role.getPrivileges()) {
				authorities.add(new SimpleGrantedAuthority(privilege.getName())); 
			}
		}
		return authorities;
	}
}
