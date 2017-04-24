/**
 * 
 */
package enterprises.mccollum.wmapp.ssauthclient;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.ejb.Schedule;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import enterprises.mccollum.wmapp.authobjects.UserTokenBean;

/**
 * @author smccollum
 *
 */
@Singleton
@Startup
public class AuthDBCleaner {
	@Inject
	UserTokenBean tokenBean;
	
	@PostConstruct
	public void init(){
		//probably nothing to init
	}
	
	@Schedule(dayOfWeek="*", hour="3", info="Remove all blacklisted tokens which are past their expiration date from the database")
	public void removeExpired(){
		Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.INFO, String.format("%d expired tokens cleaned from db", tokenBean.expireTokens()));
	}
}
