package dummy.config;

import java.util.Collection;

import org.dozer.CustomConverter;
import org.dozer.DozerBeanMapper;
import org.dozer.loader.api.BeanMappingBuilder;
import org.dozer.loader.api.FieldsMappingOptions;
import org.dozer.loader.api.TypeMappingOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import dummy.entity.Role;
import dummy.entity.User;
import dummy.model.UserEmployeeModel;

public class DTOConfigurer extends BeanMappingBuilder implements CustomConverter {

	@Autowired
	DozerBeanMapper dozermapper;
	
	@Autowired
	PasswordEncoder encoder;
	
	@Autowired
	Collection<Role> roles;
	
	Role role;
	User user;
		
	@Override
	protected void configure() {
		mapping(UserEmployeeModel.class, User.class, TypeMappingOptions.wildcard(false))
		.fields("password", "password", FieldsMappingOptions.customConverter(this.getClass()))
		.fields("roles", "roles", FieldsMappingOptions.customConverter(this.getClass()));
	}

	@Override
	public Object convert(Object existingDestinationFieldValue, Object sourceFieldValue, Class<?> destinationClass, Class<?> sourceClass){
		if (sourceFieldValue != null && sourceFieldValue instanceof String && String.class.equals(destinationClass))
			return encoder.encode(sourceFieldValue.toString());
		else if (sourceFieldValue != null && sourceFieldValue instanceof String[] && Collection.class.equals(destinationClass)) {
			String[] rolesstringarr = (String[])sourceFieldValue;
			for (String rolestring : rolesstringarr) {
				 if (rolestring.equals("ROLE_ADMIN")) {
					 role = new Role();
					 role.setId(1L);
					 role.setName("ROLE_ADMIN"); 
					 roles.add(role);
				}else if (rolestring.equals("ROLE_USER")) {
					role = new Role();
					role.setId(2L);
					role.setName("ROLE_USER"); 
					roles.add(role);
				}else if (rolestring.equals("ROLE_GUEST")) {
					role = new Role();
					role.setId(3L);
					role.setName("ROLE_GUEST"); 
					roles.add(role);
				} 
			}
			return roles;
		}
		return null;
	}
}