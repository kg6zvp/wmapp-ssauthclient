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
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.Response;

import enterprises.mccollum.CookieUtils;
import enterprises.mccollum.jee.urlutils.UrlContextUtils;
import enterprises.mccollum.jee.urlutils.UrlGeneralUtils;
import enterprises.mccollum.jee.urlutils.UrlStateUtils;
import enterprises.mccollum.ssauthclient.JWTReaderUtils;
import enterprises.mccollum.ssauthclient.PrincipalVerificationType;
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
	UrlStateUtils urlStateUtils;
	
	@Inject
	UrlContextUtils urlCtxUtils;
	
	@Inject
	UrlGeneralUtils urlUtils;
	
	String loginUrl;
	/**
	 * URL to obtain tokens with access code (OAuth)
	 */
	String tokenUrl = null;
	
	String loginserverBaseUrl = null;
	
	public static final String PARAM_AUTHORIZE_URL = "authorize-url",
								PARAM_TOKEN_URL = "token-url",
								PARAM_LOGINSERVER_BASE = "loginserver-base";
	
	public static final String LOGIN_URL_DEFAULT = "/login",
								TOKEN_URL_DEFAULT = "/api/oauth/token";

	/**
	 * Default constructor. 
	 */
	public LoginFilter(){}
	
	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig fConfig) throws ServletException {
		this.fConfig = fConfig;
		/*
		 * If the authorization URL was specified
		 */
		if(fConfig.getInitParameter(PARAM_AUTHORIZE_URL) != null){
			loginUrl = fConfig.getInitParameter(PARAM_AUTHORIZE_URL);
		}else{
			loginUrl = LOGIN_URL_DEFAULT;
		}
		logf(Level.CONFIG, "login url: %s", loginUrl);
		System.out.println("login url: "+loginUrl);
		
		/*
		 * If they specified the loginserver base url
		 * 
		 * This if statement included for readability, as it is not necessary for functionality
		 */
		if(fConfig.getInitParameter(PARAM_LOGINSERVER_BASE) != null){
			loginserverBaseUrl = fConfig.getInitParameter(PARAM_LOGINSERVER_BASE);
		}
		
		/*
		 * If they specified the token url
		 */
		if(fConfig.getInitParameter(PARAM_TOKEN_URL) != null){
			/*
			 * If they specified the absolute url
			 */
			if(urlUtils.isAbsoluteUrl(fConfig.getInitParameter(PARAM_TOKEN_URL))){
				tokenUrl = fConfig.getInitParameter(PARAM_TOKEN_URL);
			}else{ //if they specified a relative url
				/*
				 * If they specified the loginserver base url and they gave a relative token url
				 */
				if(loginserverBaseUrl != null){
					tokenUrl = loginserverBaseUrl + fConfig.getInitParameter(PARAM_TOKEN_URL);
				}else{ //if there's no base url and they gave a relative token url
					//We're stuck with a relative url
					tokenUrl = fConfig.getInitParameter(PARAM_TOKEN_URL);
				}
			}
		}
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
		boolean isLoginUrl = false;
		if(loginUrl != null){
			if(!urlUtils.isAbsoluteUrl(loginUrl)){
				String requestUri = req.getRequestURI().replace(req.getContextPath(), "");
				logf(Level.INFO, "RequestURI: %s", requestUri);
				isLoginUrl = requestUri.startsWith(loginUrl) && !(requestUri.contains("/../"));
				logf(Level.INFO, "isLoginUrl: %b", isLoginUrl);
			}
		}
		
		Object sessionPrincipal = session.getAttribute(SSAuthClient.PRINCIPAL_SESSION_ATTRIBUTE);
		
		if(sessionPrincipal != null && sessionPrincipal instanceof WMPrincipal){ //if the user is already in session
			if( !tokenVerifier.checkBlacklisted(((WMPrincipal)sessionPrincipal).getToken()) ){ //if this token is blacklisted
				logf(Level.WARNING, "Removed bad user from session: %s", ((WMPrincipal)sessionPrincipal).getToken().getTokenId());
				session.removeAttribute(SSAuthClient.PRINCIPAL_SESSION_ATTRIBUTE);
			}else{
				req.setUserPrincipal((WMPrincipal)sessionPrincipal);
				req.setPrincipalVerifyType(PrincipalVerificationType.SESSION);
				logf(Level.FINE, "User %s already in session", ((WMPrincipal) sessionPrincipal).getName());
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
					req.setPrincipalVerifyType(PrincipalVerificationType.COOKIE);
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
					req.setPrincipalVerifyType(PrincipalVerificationType.AUTHORIZATION_HEADER);
					logf(Level.FINE, "Using token from auth header: %s", tokenString);
				}
			}
		}//*/
		
		/**
		 * Check token header
		 */
		if(tokenString == null){
			if(req.getHeader(UserToken.TOKEN_HEADER) != null){
				tokenString = req.getHeader(UserToken.TOKEN_HEADER);
				req.setPrincipalVerifyType(PrincipalVerificationType.TOKEN_HEADER);
			}
		}//*/
		
		/**
		 * See if it's a param from OAuth
		 */
		if(tokenString == null){
			String tokenParam = req.getParameter("token");
			if(tokenParam != null){
				tokenString = tokenParam;
				req.setPrincipalVerifyType(PrincipalVerificationType.URL_PARAM);
			}
		}
		
		/**
		 * See if there's a 'code' param from OAuth
		 */
		if(tokenString == null){
			String codeParam = req.getParameter("code");
			if(codeParam != null){
				Client client = ClientBuilder.newClient();
				Response r = null;
				if(urlUtils.isAbsoluteUrl(tokenUrl)){
					r = client.target(tokenUrl).request().get();
				}else{
					r = client.target(urlCtxUtils.getApplicationBaseUrl(req)+tokenUrl).request().get();
				}
				/*
				 * As long as we got a real response that's a 200
				 */
				if(r != null && r.getStatus() == 200){
					tokenString = r.getEntity().toString();
					logf(Level.INFO, "Using code parameter, obtained token: %s", tokenString);
					req.setPrincipalVerifyType(PrincipalVerificationType.CODE_PARAM);
				}else{
					logf(Level.WARNING, "Failed to get code with status %d and message %s", r.getStatus(), r.getEntity().toString());
				}
			}
		}
		
		if(tokenString != null){ //if the user can be recognized as logged in
			logf(Level.FINE, "Found a token %s, attempting verification", tokenString);
			wmFilter(req, res, session, tokenString);
		}//*/
		
		/**
		 * If they're logged in: send them on their way
		 * or
		 * if they're not logged in, but headed for the login url
		 */
		if( (req.getUserPrincipal() != null && (req.getUserPrincipal() instanceof WMPrincipal))
				|| (sessionPrincipal != null && (sessionPrincipal instanceof WMPrincipal))
			|| isLoginUrl ){
			// pass the request along the filter chain
			chain.doFilter(req, res);
		}else{ //if they're not logged in and not headed for the login url
			/*String redirectURL = String.format("%s?%s=%s",
					isAbsoluteLoginUrl ? loginURL : urlCtxUtils.getApplicationBaseUrl(req)+loginURL, //login url as given in the filter parameter
							"redirect_uri", urlStateUtils.encodeRequestUrlToParam(req));//*/
			String redirectURL = urlUtils.addParamToUrl((urlUtils.isAbsoluteUrl(loginUrl) ? loginUrl : urlCtxUtils.getApplicationBaseUrl(req)+loginUrl),
					String.format("%s=%s", "redirect_uri", urlStateUtils.encodeRequestUrlToParam(req)),
					String.format("%s=%b", "encoded_uri", true));
			res.sendRedirect(redirectURL);
		}
	}
	
	private void wmFilter(ServletRequestProxy req, HttpServletResponse res, HttpSession session, String jwt) {
		UserToken userToken = jwtRdr.verifyJwt(jwt, UserToken.class, true); //use exclusions because UserToken needs them
		if(userToken == null){
			logf(Level.WARNING, "Failed to verify token: %s", jwt);
			if(req.getPrincipalVerifyType() == PrincipalVerificationType.COOKIE)
				CookieUtils.deleteCookie(res, UserToken.TOKEN_HEADER);
			return;
		}
		if(tokenVerifier.checkToken(userToken)){
			WMPrincipal principal = new WMPrincipal(userToken, jwt);
			req.setUserPrincipal(principal);
			session.setAttribute(SSAuthClient.PRINCIPAL_SESSION_ATTRIBUTE, principal);
			/*
			 * If the token was given as a URL Parameter or a code parameter, set the cookie on their machine
			 */
			if(req.getPrincipalVerifyType() == PrincipalVerificationType.URL_PARAM
				|| req.getPrincipalVerifyType() == PrincipalVerificationType.CODE_PARAM){
				CookieUtils.setCookie(res, UserToken.TOKEN_HEADER, jwt, userToken.getJavaExpirationDate());
			}
		}else{
			if(req.getPrincipalVerifyType() == PrincipalVerificationType.COOKIE)
				CookieUtils.deleteCookie(res, UserToken.TOKEN_HEADER);
		}
	}
	
	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {}
	
	
	private void logf(Level lvl, String fmt, Object...args){
		Logger.getLogger(LoginFilter.class.getSimpleName()).log(lvl, String.format(fmt, args));
	}
}
