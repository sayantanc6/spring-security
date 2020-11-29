package dummy.model;

public class AuthorizationUrl {
	
	private String clientName;
	private String oauth2AuthenticationUrls;
	
	public AuthorizationUrl(String clientName, String oauth2AuthenticationUrls) {
		this.clientName = clientName;
		this.oauth2AuthenticationUrls = oauth2AuthenticationUrls;
	}
	
	public String getClientName() {
		return clientName;
	} 

	public void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public String getOauth2AuthenticationUrls() {
		return oauth2AuthenticationUrls;
	}

	public void setOauth2AuthenticationUrls(String oauth2AuthenticationUrls) {
		this.oauth2AuthenticationUrls = oauth2AuthenticationUrls;
	}

	@Override
	public String toString() {
		return "AuthorizationUrl [clientName=" + clientName + ", oauth2AuthenticationUrls=" + oauth2AuthenticationUrls
				+ "]";
	}

}
