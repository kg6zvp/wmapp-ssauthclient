package enterprises.mccollum.wmapp.ssauthclient;

import javax.ejb.Stateless;
import javax.inject.Inject;

import enterprises.mccollum.wmapp.authobjects.UserToken;
import enterprises.mccollum.wmapp.authobjects.UserTokenBean;

import javax.ejb.Local;

@Local
@Stateless
public class TokenChecker {
	@Inject
	UserTokenBean tokenBean;
	
	/**
	 * Performs logical checks on a token (assumes the token's signature was already verified using the JWT reader!)
	 * 
	 * Examples of logical checks are verification of expiration date, checking against the database to verify that there isn't a newer token in the db, etc.
	 * 
	 * @param token: The token to logically check
	 * @return: true if it passed, false if not
	 */
	public boolean checkToken(UserToken token){
		UserToken dbToken = tokenBean.getByTokenId(token.getTokenId());
		if(dbToken.getBlacklisted())
			return false;
		if(token.getBlacklisted()){
			dbToken.setBlacklisted(true);
			tokenBean.save(dbToken);
			return false;
		}
		/**
		 * If the supplied token is older than the one in the database, reject it
		 */
		if(token.getExpirationDate() < dbToken.getExpirationDate()){
			return false;
		}
		/**
		 * If the expiration date for the 
		 */
		if(token.getExpirationDate() < (System.currentTimeMillis()/1000) ){
			return false;
		}
		return true;
	}
	
	/**
	 * Only checks the token to see if it has been blacklisted (forcibly logged out)
	 * 
	 * @param token: The token to check for blacklisting
	 * 
	 * @return: true if it's still okay, false if it's been blacklisted
	 */
	public boolean checkBlacklisted(UserToken token){
		UserToken dbToken = tokenBean.getByTokenId(token.getTokenId());
		if(dbToken.getBlacklisted())
			return false;
		if(token.getBlacklisted()){
			dbToken.setBlacklisted(true);
			tokenBean.save(dbToken);
			return false;
		}
		return true;
	}
}
