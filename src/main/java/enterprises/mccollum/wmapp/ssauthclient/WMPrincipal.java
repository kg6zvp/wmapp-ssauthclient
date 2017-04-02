/**
 * 
 */
package enterprises.mccollum.wmapp.ssauthclient;

import java.security.Principal;

import enterprises.mccollum.wmapp.authobjects.UserToken;

/**
 * @author smccollum
 *
 */
public class WMPrincipal implements Principal {
	private UserToken token;
	private String tokenSignature;
	
	public WMPrincipal() {}
	public WMPrincipal(UserToken token, String tokenSignature){
		setToken(token);
		setTokenSignature(tokenSignature);
	}
	
	/* (non-Javadoc)
	 * @see java.security.Principal#getName()
	 */
	@Override
	public String getName() {
		return token.getUsername();
	}
	
	public UserToken getToken(){
		return token;
	}
	
	public void setToken(UserToken token){
		this.token = token;
	}
	public String getTokenSignature() {
		return tokenSignature;
	}
	public void setTokenSignature(String tokenSignature) {
		this.tokenSignature = tokenSignature;
	}
}