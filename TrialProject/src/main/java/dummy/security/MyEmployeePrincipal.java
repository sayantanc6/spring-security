package dummy.security;

import java.util.Collection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import dummy.entity.User;

@Component
public class MyEmployeePrincipal implements UserDetails {
	
	User emp;
	
	@Autowired
	MyUserDetailsService service;
	
	public MyEmployeePrincipal(User empDetails) {
		this.emp = empDetails;
	}

	public MyEmployeePrincipal() {
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return service.getAuthorities(emp.getRoles()); 
	}

	@Override
	public String getPassword() {
		return emp.getPassword(); 
	}

	@Override
	public String getUsername() {
		return emp.getEmail();
	}

	@Override
	public boolean isAccountNonExpired() {
		return !emp.isTokenExpired(); 
	}

	@Override
	public boolean isAccountNonLocked() {
		return !emp.isTokenExpired();
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return !emp.isTokenExpired(); 
	}

	@Override
	public boolean isEnabled() {
		return !emp.isTokenExpired();
	}
	
	public User getUser() {
        return emp;
	}
}
