package enterprises.mccollum.wmapp.ssauthclient;

import java.io.IOException;
import java.lang.annotation.Annotation;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;

import javax.inject.Inject;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;

import enterprises.mccollum.wmapp.authobjects.UserGroup;
import enterprises.mccollum.wmapp.authobjects.UserToken;

@Provider
public class AuthRequestFilter implements ContainerRequestFilter{

	@Inject
	PublicKeySingleton pks;
	
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
		}
		return true;
	}
	
	@Override
	public void filter(ContainerRequestContext requestContext) throws IOException {
		if(resourceInfo.getResourceClass().getAnnotation(WestmontOnly.class) == null
				&& resourceInfo.getResourceMethod().getAnnotation(WestmontOnly.class) == null)
			return; //if the class and method don't care about being secured, we don't either
		
		String tokenString = requestContext.getHeaderString(UserToken.TOKEN_HEADER);
		
		String signatureB64 = requestContext.getHeaderString(UserToken.SIGNATURE_HEADER);

		if(!validateTokenSig(requestContext, tokenString, signatureB64)){
			abort(requestContext);
			return;
		}
		UserToken token = null;
		try{
			Gson gson = new Gson();
			token = gson.fromJson(tokenString, UserToken.class);
		}catch(JsonSyntaxException e){
			abort(requestContext); //if we can't instantiate an object, get out
			return;
		}
		
		if(token.getExpirationDate() <= System.currentTimeMillis()){ //check expiration date
			abort(requestContext); //it's expired already
			return;
		}
		
		if(!checkAuthorization(token)){
			abort(requestContext);
			return;
		}
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
				if(et.equals(token.getEmployeeType()))
					pass = true;
			}
			if(!pass)
				return false;
		}
		
		/*NO NEED FOR THIS BLOCK RIGHT NOW
		UserGroupsOnly ugAnno = null;
		if((temp = resourceInfo.getResourceMethod().getAnnotation(UserGroupsOnly.class)) != null)
			ugAnno = (UserGroupsOnly) temp;
		else if((temp = resourceInfo.getResourceClass().getAnnotation(UserGroupsOnly.class)) != null)
			ugAnno = (UserGroupsOnly) temp;
		if(ugAnno != null){
			for(String gName : ugAnno.value()){
				if(!userInGroup(token, gName))
					return false;
			}
		}//*/
		return true;
	}

	private boolean userInGroup(UserToken token, String gName) {
		for(UserGroup group : token.getGroups()){
			if(group.getName().equals(gName))
				return true;
		}
		return false;
	}

	private void abort(ContainerRequestContext requestContext) {
		requestContext.abortWith(Response.status(Status.UNAUTHORIZED).build());
	}
}
