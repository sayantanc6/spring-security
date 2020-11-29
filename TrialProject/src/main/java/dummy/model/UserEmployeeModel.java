package dummy.model;

import java.io.Serializable;

import javax.validation.constraints.NotBlank;

import org.dozer.Mapping;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.annotation.JsonProperty;

import dummy.util.FieldsValueMatch;
 
@Component
@FieldsValueMatch.List(@FieldsValueMatch(field = "password",fieldMatch = "repeatPassword",message = "Passwords do not match!"))
public class UserEmployeeModel implements Serializable{
	
	private static final long serialVersionUID = 42L;
	
	@JsonProperty("id")
	@Mapping("id")
	 private Long id;
	 
	@NotBlank(message = "name must not be blank")
	@JsonProperty("firstName")
	@Mapping("firstName")
    private String firstName;
	
	@JsonProperty("lastName")
	@Mapping("lastName")
    private String lastName;
	
	@JsonProperty("email")
	@Mapping("email")
    private String email;
	
	@JsonProperty("password")
	@Mapping("password")
    private String password;
	
	@JsonProperty("repeatPassword")
	@Mapping("this")
    private String repeatPassword;
	
	@JsonProperty("enabled") 
	@Mapping("enabled")
    private boolean enabled;
	
	@JsonProperty("tokenExpired")
    private boolean tokenExpired;
    
	@JsonProperty("roles")
	@Mapping("roles") 
    private String[] roles;
    
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getRepeatPassword() {
		return repeatPassword;
	}

	public void setRepeatPassword(String repeatPassword) {
		this.repeatPassword = repeatPassword;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean isTokenExpired() {
		return tokenExpired;
	}

	public void setTokenExpired(boolean tokenExpired) {
		this.tokenExpired = tokenExpired;
	}

	public String[] getRoles() {
		return roles;
	}

	public void setRoles(String[] roles) {
		this.roles = roles;
	}

	@Override
	public String toString() {
		return "UserEmployeeModel [id=" + id + ", firstName=" + firstName + ", lastName=" + lastName + ", email="
				+ email + ", password=" + password + ", enabled=" + enabled + ", tokenExpired=" + tokenExpired
				+ ", roles=" + roles + "]";
	}
}
