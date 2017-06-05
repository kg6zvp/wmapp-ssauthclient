package enterprises.mccollum.wmapp.ssauthclient;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class ServletRequestProxy extends HttpServletRequestWrapper {
	private Principal principal;

	public ServletRequestProxy(HttpServletRequest request) {
		super(request);
		setUserPrincipal(super.getUserPrincipal());
	}
	
	public void setUserPrincipal(Principal principal){
		this.principal = principal;
	}

	@Override
	public Principal getUserPrincipal() {
		return principal;
	}
}
