package enterprises.mccollum.wmapp.ssauthclient;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import enterprises.mccollum.ssauthclient.JWTReaderUtils;
import enterprises.mccollum.ssauthclient.URLStateUtils;
import enterprises.mccollum.wmapp.authobjects.UserToken;

/**
 * Servlet Filter implementation class SSAuthClientFilter
 */
public class LoginFilter implements Filter {
	FilterConfig fConfig;
	
	@Inject
	JWTReaderUtils jwtRdr;
	
	@Inject
	TokenChecker tokenVerifier;
	
	@Inject
	URLStateUtils urlStateUtils;
	
	String loginURL;
	
	public static final String PARAM_LOGIN_URL = "login-url";

	/**
	 * Default constructor. 
	 */
	public LoginFilter(){}
	
	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig fConfig) throws ServletException {
		this.fConfig = fConfig;
		if(fConfig.getInitParameter(PARAM_LOGIN_URL) != null){
			loginURL = fConfig.getInitParameter(PARAM_LOGIN_URL);
		}else{
			loginURL = null;
		}
		logf(Level.CONFIG, "Setting login url to %s", loginURL);
		//urlStateUtils = new URLStateUtils();
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		logf(Level.INFO, "LoginFilter invoked");
		ServletRequestProxy req = new ServletRequestProxy((HttpServletRequest)request);
		HttpServletResponse res = (HttpServletResponse) response;
		HttpSession session = req.getSession();
		/*
		 * Determing whether it's the login url
		 */
		logf(Level.INFO, "RequestURI: %s", req.getRequestURI());
		boolean isLoginUrl = req.getRequestURI().startsWith(loginURL) && !(req.getRequestURI().contains("/../"));
		logf(Level.INFO, "isLoginUrl: %b", isLoginUrl);
		
		Object sessionPrincipal = session.getAttribute(SSAuthClient.PRINCIPAL_SESSION_ATTRIBUTE);
		
		if(sessionPrincipal != null && sessionPrincipal instanceof WMPrincipal){ //if the user is already in session
			if( !tokenVerifier.checkBlacklisted(((WMPrincipal)sessionPrincipal).getToken()) ){ //if this token is blacklisted
				logf(Level.WARNING, "Removed bad user from session: %s", ((WMPrincipal)sessionPrincipal).getToken().getTokenId());
				session.removeAttribute(SSAuthClient.PRINCIPAL_SESSION_ATTRIBUTE);
			}else{
				req.setUserPrincipal((WMPrincipal)sessionPrincipal);
				System.out.println("User already in session");
				chain.doFilter(req, res);
				return;
			}
		}
		/**
		 * If we got here, they aren't logged in
		 */
		String tokenString = null;
		
		/**
		 * Check cookies
		 */
		if(req.getCookies() != null){ //if there are cookies
			Eat_Cookies: for(Cookie cookie : req.getCookies()){
				if(cookie.getName().equals(UserToken.TOKEN_HEADER)){ //if we found the token
					tokenString = cookie.getValue();
					break Eat_Cookies; //no need to keep on looping
				}
			}
		}//*/
		
		/**
		 * Check authorization header
		 */
		if(tokenString == null){
			String authHeader = req.getHeader("Authorization");
			if(authHeader != null){
				String[] parts = authHeader.split(" ");
				if(parts[0].equalsIgnoreCase("bearer")){
					tokenString = parts[1];
					System.out.println(String.format("Using token from auth header: %s", tokenString));
				}
			}
		}//*/
		
		/**
		 * Check token header
		 */
		if(tokenString == null){
			tokenString = req.getHeader(UserToken.TOKEN_HEADER);
		}//*/
		
		/**
		 * See if it's a param from OAuth
		 */
		if(tokenString == null){
			String tokenParam = req.getParameter("token");
			if(tokenParam != null)
				tokenString = tokenParam;
		}
		
		if(tokenString != null){ //if the user can be recognized as logged in
			System.out.println("Found a token, attempting verification");
			wmFilter(req, res, session, tokenString);
		}//*/
		
		/**
		 * If they're logged in: send them on their way
		 * or
		 * if they're not logged in, but headed for the login url
		 */
		if(sessionPrincipal != null && (sessionPrincipal instanceof WMPrincipal) || isLoginUrl){
			// pass the request along the filter chain
			chain.doFilter(req, res);
		}else{ //if they're not logged in and not headed for the login url
			//String urlToParams = req.getRequestURL().toString()+getParameterString(req.getParameterMap());
			String redirectURL = String.format("%s?%s=%s", loginURL, "after", urlStateUtils.encodeRequestUrlToParam(req));
			res.sendRedirect(redirectURL);
		}
	}
	
	private void wmFilter(ServletRequestProxy req, HttpServletResponse res, HttpSession session, String jwt) {
		UserToken userToken = jwtRdr.verifyJwt(jwt, UserToken.class, true); //use exclusions because UserToken needs them
		if(userToken == null){
			logf(Level.INFO, "Failed to verify token: %s", jwt);
			return;
		}
		if(tokenVerifier.checkToken(userToken)){
			WMPrincipal principal = new WMPrincipal(userToken, jwt);
			req.setUserPrincipal(principal);
			session.setAttribute(SSAuthClient.PRINCIPAL_SESSION_ATTRIBUTE, principal);
		}
	}
	
	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {}
	
	
	private void logf(Level lvl, String fmt, Object...args){
		Logger.getLogger("LoginFilter").log(lvl, String.format(fmt, args));
	}
}
