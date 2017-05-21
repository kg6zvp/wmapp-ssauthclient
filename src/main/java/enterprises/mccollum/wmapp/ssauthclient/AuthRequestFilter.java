package enterprises.mccollum.wmapp.ssauthclient;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.Signature;
import java.util.Base64;
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

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import enterprises.mccollum.wmapp.authobjects.UserToken;
import enterprises.mccollum.wmapp.authobjects.UserTokenBean;

@Provider
public class AuthRequestFilter implements ContainerRequestFilter{

	@Inject
	PublicKeySingleton pks;
	
	@Inject
	UserTokenBean tokenBean;
	
	@Context
	ResourceInfo resourceInfo;
	
	private boolean validateTokenSig(ContainerRequestContext ctx, String tokenString, String sigB64){
		if(tokenString == null || sigB64 == null){
			return false;
		}

		byte[] tokenBytes = tokenString.getBytes(StandardCharsets.UTF_8);
		byte[] signature = Base64.getDecoder().decode(sigB64);
		try {
			Signature verifier = Signature.getInstance("SHA256withRSA");
			verifier.initVerify(pks.getPublicKey());
			verifier.update(tokenBytes);
			if(!verifier.verify(signature)){ //couldn't verify signature
				return false;
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		boolean filter = (resourceInfo.getResourceClass().getAnnotation(EmployeeTypesOnly.class) != null
						|| resourceInfo.getResourceMethod().getAnnotation(EmployeeTypesOnly.class) != null);
		
		Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.INFO, "JAX-RS authentication filter invoked");
		
		final String tokenString = requestContext.getHeaderString(UserToken.TOKEN_HEADER);
		
		final String signatureB64 = requestContext.getHeaderString(UserToken.SIGNATURE_HEADER);

		if(!validateTokenSig(requestContext, tokenString, signatureB64)){
			if(filter)
				abort(requestContext, Status.NOT_ACCEPTABLE, "Invalid token signature");
			return;
		}
		final UserToken token;
		try{
			Gson gson = new Gson();
			token = gson.fromJson(tokenString, UserToken.class);
		}catch(JsonSyntaxException e){
			if(filter)
				abort(requestContext, Status.NOT_ACCEPTABLE, "Unable to instantiate an instance of the token object from the provided json; your token isn't a token"); //if we can't instantiate an object, get out
			return;
		}
		
		//check against reuse of already expired token
		UserToken dbToken = null;
		if( (dbToken = tokenBean.getByTokenId(token.getTokenId())) != null){ //if we have a token matching it in the database
			if(dbToken.getExpirationDate() > token.getExpirationDate()){ //if the token is an old one
				if(filter)
					abort(requestContext, Status.UNAUTHORIZED, "Use of an old token not permitted");
				return; //peace out so we don't save the bad token to the SecurityContext
			}
		}
		
		if(token.getExpirationDate() <= System.currentTimeMillis()){ //check expiration date
			if(filter)
				abort(requestContext, Status.UNAUTHORIZED, "Token expired"); //it's expired already
			return;
		}
		
		if(isBlacklisted(dbToken, token) && filter){
			if(token.getBlacklisted()){ //if the token passed to the endpoint was marked as blacklisted
				abort(requestContext, Status.OK, "Token blacklisted successfully");
			}else{
				abort(requestContext, Status.UNAUTHORIZED, "Token is blacklisted");
			}
			return;
		}
		
		if(!checkAuthorization(token)){
			abort(requestContext, Status.FORBIDDEN, "EmployeeType not authorized");
			return;
		}
		
		requestContext.setSecurityContext(new SecurityContext() {
			@Override
			public boolean isUserInRole(String role) {
				//TODO: Move this into true roles instead of employeeType checking
				return token.getEmployeeType().equals(role);
			}
			
			@Override
			public boolean isSecure() {
				return true;
			}
			
			@Override
			public Principal getUserPrincipal() {
				return new WMPrincipal(token, tokenString, signatureB64);
			}
			
			@Override
			public String getAuthenticationScheme() {
				return null;
			}
		});
	}

	/**
	 * Checks the database to see if the token we were given has been blacklisted
	 * @param dt: Token taken from the database (so we don't have to run the same query again)
	 * @param token: Token provided in the Token header
	 * @return
	 */
	private boolean isBlacklisted(UserToken dt, UserToken token) {
		//UserToken dt = tokenBean.getByTokenId(token.getTokenId());
		if(dt == null){ //If the token wasn't found in the database
			if(token.getBlacklisted())
				tokenBean.save(token); //save token to database so that it will show as blacklisted in future
			return token.getBlacklisted();
		}
		System.out.println("Token found: "+new Gson().toJson(dt));
		return dt.getBlacklisted(); //if the token was found in the database, we'll reach here and will trust the database over the token itself
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
