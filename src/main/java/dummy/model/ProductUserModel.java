package dummy.model;

import org.springframework.stereotype.Component;

import com.google.gson.annotations.SerializedName;

import dummy.security.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
 
@Component
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProductUserModel {

	@SerializedName("username")
	private String username;
	
	@SerializedName("password")
	private String password;

	@SerializedName("role")
	private Role role;
}
