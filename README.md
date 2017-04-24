# Server-Side Auth Client

This is a client for the authentication server designed for use in JavaEE micro-services that authenticate and authorize users based on the central auth system.

## Usage

### Add authorization SDK to your project

Add the maven dependency to your project: (If you don't know what we're talking about, google or ask for help from an upperclassman)

~~~~ {.xml .numberLines}
<dependency>
	<groupId>enterprises.mccollum.wmapp</groupId>
	<artifactId>ssauthclient</artifactId>
	<version>0.0.2-SNAPSHOT</version>
	<scope>compile</scope>
</dependency>
~~~~

Add a `<class/>` declaration to your persistence.xml file for each of the classes used:
The lines should look like: `<class>enterprises.mccollum.wmapp.authobjects.DomainUser</class>`
`<class>enterprises.mccollum.wmapp.authobjects.UserGroup</class>`
`<class>enterprises.mccollum.wmapp.authobjects.UserToken</class>`
`<class>enterprises.mccollum.wmapp.authobjects.InvalidationSubscription</class>`

Once included in the file, your persistence.xml file may look like this:

~~~~ {.xml .numberLines}
<?xml version="1.0" encoding="UTF-8"?>
<persistence version="2.1" xmlns="http://xmlns.jcp.org/xml/ns/persistence" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/persistence http://xmlns.jcp.org/xml/ns/persistence/persistence_2_1.xsd">
    <persistence-unit name="sampleservice">
		<class>enterprises.mccollum.wmapp.authobjects.DomainUser</class>
		<class>enterprises.mccollum.wmapp.authobjects.UserGroup</class>
		<class>enterprises.mccollum.wmapp.authobjects.UserToken</class>
		<class>enterprises.mccollum.wmapp.authobjects.InvalidationSubscription</class>
        <properties>
			<property name="hibernate.hbm2ddl.auto" value="update"/>
            <property name="hibernate.hbm2ddl.import_files_sql_extractor" value="org.hibernate.tool.hbm2ddl.MultipleLinesSqlCommandExtractor" />
        </properties>
    </persistence-unit>
</persistence>
~~~~

IMPORTANT NOTE: If you change the version number in your maven dependency, the filename in the `<jar-file/>` declaration must be modified to match. If your SDK version in maven is `1.2.5-RELEASE`, then your jar-file declaration should be: `<jar-file>lib/ssauthclient-1.2.5-RELEASE.jar</jar-file>`

### Use it in your code

You must annotate any secured JAX-RS endpoings (either the classes or the methods) with the @EmployeeTypesOnly annotation.

An example of this would be the following:

~~~~ {.java .numberLines}
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import enterprises.mccollum.wmapp.ssauthclient.EmployeeTypesOnly;
import enterprises.mccollum.wmapp.ssauthclient.WMPrincipal;

@Path("sample")
public class SampleService {
    @Context
    SecurityContext seCtx;
    
    @GET
    @EmployeeTypesOnly("*") //allows everyone with a Westmont username and password to access this endpoint
    public String getTime(){
        WMPrincipal pr = (WMPrincipal) seCtx.getUserPrincipal();
        return String.valueOf(pr.getToken().getDeviceName()
                            +": "+System.currentTimeMillis()); //returns a string like: "deviceName: timeInMilliseconds"
    }   
    
    @GET
    @Path("studentTime")
    @EmployeeTypesOnly("student") //only allow students to use this API endpoint
    public String getStudentTime(){
        return "student: "+String.valueOf(System.currentTimeMillis());
    }   
    
    @GET
    @Path("scTime")
    @EmployeeTypesOnly({"student", "community"}) //Allow students and community (usually this is graduates of Westmont) to use this, but not faculty and staff, etc.
    public String getEveryoneTime(){
        return "Students/Community: "+String.valueOf(System.currentTimeMillis());
    }   
}
~~~~

### (OPTIONAL) Add environment variable to the container you will be deploying in

The environment your java container server is being deployed in must contain the variable `WMKS_PUBKEY_FILE` which contains the complete path of the java keystore file containing the key with alias `WMAUTH` secured with the password `password`

#### systemd

Add the following directive under the [Service] heading inside wildfly.service (assuming your service is named wildfly.service)
`Environment=WMKS_PUBKEY_FILE=/opt/wmks.jks`

Example configuration snippet from a wildfly 10 systemd service file:

~~~~ {.numberLines}
[Service]
Environment=LAUNCH_JBOSS_IN_BACKGROUND=1
Environment=WMKS_PUBKEY_FILE=/opt/wmks.jks
User=wildfly
ExecStart=/opt/wildfly/bin/standalone.sh --server-config=standalone-full.xml -b=127.0.0.1
~~~~

~~~~ {.java .numberLines}
public static final String KEYSTORE_PATH = System.getenv("WMKS_PUBKEY_FILE");
private static final char[] KEYSTORE_PASS = "password".toCharArray();
    
public static final String KEY_ALIAS = "WMAUTH";
~~~~
