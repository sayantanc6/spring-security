package dummy.security;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

import dummy.entity.User;

public class CustomMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {
	
	private Object filterObject;
    private Object returnObject;
    
    public CustomMethodSecurityExpressionRoot(Authentication authentication) {
        super(authentication);
    } 
    
    public boolean isMember(String username) {
    	User useremp = ((MyEmployeePrincipal)this.getPrincipal()).getUser();
    	return useremp.getEmail().equals(username);
	} 

	@Override
	public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
	}

	@Override
	public Object getFilterObject() {
		return this.filterObject;
	}

	@Override
	public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
	}

	@Override
	public Object getReturnObject() {
		return this.returnObject;
	}

	@Override
	public Object getThis() {
		return this;
	}
}
