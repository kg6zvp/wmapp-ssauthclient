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
	private String tokenString;
	
	public WMPrincipal() {}
	public WMPrincipal(UserToken token, String tokenString){
		setToken(token);
		setTokenString(tokenString);
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
	public String getTokenString() {
		return tokenString;
	}
	public void setTokenString(String tokenString) {
		this.tokenString = tokenString;
	}
}