# spring-openid-client
Spring Security OpenID client implementation (demo use case)
The app runs on port 7000 so that you can run both, UAA and this app on the same machine. 
The app is configured to use private key JWT for client authentication, so you can test this authentication method with UAA. 
The app also exposes a JWKS URI at http://localhost:7000/jwks_uri where UAA can retrieve the public keys to verify the JWTs sent by this app.

## Quick Start

Requirements:
* Java 21 (minimum)

Start a UAA locally, for this please follow the instructions in the UAA repository, e.g. https://github.com/cloudfoundry/uaa?tab=readme-ov-file#running-as-a-spring-boot-application

    $ git clone git://github.com/cloudfoundry/uaa.git
    $ cd uaa


Pre-requisites for running the UAA using this demo app with private key jwt: Maintain in UAA sub-directory `scripts/boot/` the file uaa.yml with the following content:
Ensure following client is created in UAA with the following command:

```yaml
          id: client_with_allowpublic_and_jwks_uri_trust
          authorized-grant-types: 'authorization_code,client_credentials,refresh_token,password,urn:ietf:params:oauth:grant-type:jwt-bearer'
          scope: 'openid,password.write,scim.userids,cloud_controller.read,cloud_controller.write'
          authorities: 'password.write,scim.userids,cloud_controller.read,cloud_controller.write,uaa.resource'
          autoapprove: 'true'
          allowpublic: 'true'
          redirect-uri: 'http://localhost/*,http://localhost:8080/**,http://localhost:7000/**'
          jwks_uri: 'http://localhost:7000/jwks_uri'
```

Start the UAA with uaa.yml configuration

          $ java -DCLOUDFOUNDRY_CONFIG_PATH=`pwd`/scripts/boot -DSECRETS_DIR=`pwd`/scripts/boot -Djava.security.egd=file:/dev/./urandom -Dmetrics.perRequestMetrics=true -Dserver.servlet.context-path=/uaa -Dserver.tomcat.basedir=`pwd`/scripts/boot/tomcat -Dlogging.config=`pwd`/scripts/boot/log4j2.properties -Dsmtp.host=localhost -Dsmtp.port=2525 -Dspring.profiles.active=hsqldb -Dstatsd.enabled=true -Dfile.encoding=UTF-8 -Duser.country=US -Duser.language=en -Duser.variant -jar `pwd`/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war

Start now this demo app

    $ git clone git@github.com:strehle/spring-openid-client.git
    $ cd spring-openid-client
    $ ./gradlew bootRun

After start of this demo app, ensure, that you see keys in http://localhost:7000/jwks_uri
Hint: you can define your own keys in `src/main/resources` and adjust the path in `application.yml` if needed. If no keys are found, 
the demo app will generate a new key pair on startup and expose the public key at http://localhost:7000/jwks_uri
UAA can use these keys to verify the JWTs sent by this demo app.  