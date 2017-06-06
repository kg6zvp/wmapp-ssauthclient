package enterprises.mccollum.wmapp.ssauthclient;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import enterprises.mccollum.ssauthclient.PrincipalVerificationType;

public class ServletRequestProxy extends HttpServletRequestWrapper {
	private Principal principal;
	
	PrincipalVerificationType principalVerifyType = null;
	
	public ServletRequestProxy(HttpServletRequest request) {
		super(request);
		setUserPrincipal(super.getUserPrincipal());
	}
	
	/**
	 * Get the verification/identity establishment/authentication passing method for this request
	 * 
	 * @return the {@link PrincipalVerificationType} used to authenticate the request
	 */
	public PrincipalVerificationType getPrincipalVerifyType() {
		return principalVerifyType;
	}
	
	/**
	 * Set the verification mechanism/identity establishment/authentication passing method for this request
	 * @param principalVerifyType: The verification type used in this request {@link PrincipalVerificationType}
	 */
	public void setPrincipalVerifyType(PrincipalVerificationType principalVerifyType) {
		this.principalVerifyType = principalVerifyType;
	}
	public void setUserPrincipal(Principal principal){
		this.principal = principal;
	}
	@Override
	public Principal getUserPrincipal() {
		return principal;
	}
}
