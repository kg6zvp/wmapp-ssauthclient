package enterprises.mccollum.wmapp.ssauthclient;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import enterprises.mccollum.ssauthclient.JWTReaderUtils;
import enterprises.mccollum.wmapp.authobjects.UserToken;
import enterprises.mccollum.wmapp.authobjects.UserTokenBean;

@Provider
public class AuthRequestFilter implements ContainerRequestFilter{
	@Inject
	JWTReaderUtils jwtRdr;
	
	@Inject
	TokenChecker tokenVerifier;
	
	@Context
	ResourceInfo resourceInfo;

	@Inject
	UserTokenBean tokenBean;
	
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		boolean filter = (resourceInfo.getResourceClass().getAnnotation(EmployeeTypesOnly.class) != null
						|| resourceInfo.getResourceMethod().getAnnotation(EmployeeTypesOnly.class) != null);
		
		logf(Level.INFO, "JAX-RS authentication filter invoked");
		
		String tokenString = null;
		
		/**
		 * Check authorization header
		 */
		if(true){ //if(tokenString == null){
			String authHeader = requestContext.getHeaderString("Authorization");
			if(authHeader != null){
				String[] parts = authHeader.split(" ");
				if(parts[0].equalsIgnoreCase("bearer")){
					tokenString = parts[1];
					logf(Level.INFO, "Using token from auth header: %s", tokenString);
				}
			}
		}
		
		/**
		 * Check token header
		 */
		if(tokenString == null){
			tokenString = requestContext.getHeaderString(UserToken.TOKEN_HEADER);
		}
		
		/**
		 * Check cookies
		 */
		if(tokenString == null){
			if(requestContext.getCookies() != null){ //if there are cookies
				if(requestContext.getCookies().containsKey(UserToken.TOKEN_HEADER)){
					tokenString = requestContext.getCookies().get(UserToken.TOKEN_HEADER).getValue();
					logf(Level.INFO, "Found token in cookies: %s", tokenString);
				}
			}
		}
		
		if(tokenString != null){ //if they are presenting us something
			wmFilter(requestContext, tokenString, filter);
		}else{
			if(filter)
				abort(requestContext, Status.UNAUTHORIZED, "Please log in");
		}
	}

	private void wmFilter(ContainerRequestContext rCtx, String tokenString, boolean filter) {
		final UserToken userToken = jwtRdr.verifyJwt(tokenString, UserToken.class, true); //use exclusions because UserToken needs them
		if(userToken == null){
			return;
		}
		if(tokenVerifier.checkToken(userToken)){
			if(filter){
				if(!checkAuthorization(userToken)){
					abort(rCtx, Status.FORBIDDEN, "You are not allowed to access this service");
					return; //peace out before we add them and abort
				}
			}
			final String fTokenString = tokenString;
			final WMPrincipal principal = new WMPrincipal(userToken, fTokenString);
			rCtx.setSecurityContext(new SecurityContext() {
				final WMPrincipal wmPrincipal = principal;
				
				@Override
				public boolean isUserInRole(String role) {
					return role.equals(wmPrincipal.getToken().getEmployeeType());
				}
				
				@Override
				public boolean isSecure() {
					return true;
				}
				
				@Override
				public Principal getUserPrincipal() {
					return wmPrincipal;
				}
				
				@Override
				public String getAuthenticationScheme() {
					return null;
				}
			});
		}
	}

	private void logf(Level logLevel, String fmt, Object...params) {
		Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(logLevel, String.format(fmt, params));
	}

	private boolean checkAuthorization(UserToken token) {
		EmployeeTypesOnly eTypeAnno = null;
		Annotation temp = null;
		if((temp = resourceInfo.getResourceMethod().getAnnotation(EmployeeTypesOnly.class)) != null)
			eTypeAnno = (EmployeeTypesOnly) temp;
		else if((temp = resourceInfo.getResourceClass().getAnnotation(EmployeeTypesOnly.class)) != null)
			eTypeAnno = (EmployeeTypesOnly) temp;
		
		if(eTypeAnno != null){
			boolean pass = false;
			for(String et : eTypeAnno.value()){
				if( (et.equals("*") && !token.getEmployeeType().equals(SSAuthClient.TEST_EMPLOYEETYPE)) || et.equals(token.getEmployeeType()))
					pass = true;
			}
			if(!pass)
				return false;
		}
		
		return true;
	}

	private void abort(ContainerRequestContext ctx, Status statusCode, JsonObject entity){
		ctx.abortWith(Response.status(statusCode).entity(entity).build());
	}
	private void abort(ContainerRequestContext requestContext, Status statusCode, String msg) {
		JsonObject entity = Json.createObjectBuilder().add("reason", msg).build();
		abort(requestContext, statusCode, entity);
	}
}
