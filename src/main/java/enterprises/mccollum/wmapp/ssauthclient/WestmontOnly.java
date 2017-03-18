package enterprises.mccollum.wmapp.ssauthclient;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;

import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Inherited
@Target({ TYPE, METHOD })
@Retention(RetentionPolicy.RUNTIME)
public @interface WestmontOnly {
}
