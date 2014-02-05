INSTALLATION AND CONFIGURATION
==============================

1. Require the bundle in your composer.json
```js
{
    "require": {
        "metaclass-nl/authentication-guard-bundle": "*@dev"
    }
}
```
2. download the bundle by:

``` bash
$ php composer.phar update metaclass-nl/authentication-guard-bundle
```

Composer will install the bundle to your `vendor/metaclass-nl` folder.

3. Add the bundle to your AppKernel

``` php
<?php
// app/AppKernel.php

public function registerBundles()
{
    $bundles = array(
        // ...
        new Metaclass\AuthenticationGuardBundle\MetaclassAuthenticationGuardBundle.php(),
    );
}
```

4. Add the following to your app/config/security.yml:

services: 
    security.authentication.listener.form:
        class: %metaclass_auth_guard.authentication.listener.form.class%
        parent: "security.authentication.listener.abstract"
        abstract: true
        calls:
            - [setGovenor, ["@metaclass_auth_guard.authentication_governor"] ] # REQUIRED

5. You may also add the following configuraton parameters (defaults shown):

metaclass_authentication_guard:
    entity_manager_login:
        name: ""
    tresholds_governor_params:
        counterDurationInSeconds:  300
        blockUsernamesFor: "10 days" 
        limitPerUserName: 3
        blockIpAddressesFor: "15 minutes"
        limitBasePerIpAddress: 10
        releaseUserOnLoginSuccess: false
        allowReleasedUserOnAddressFor: "30 days"
        allowReleasedUserOnAgentFor: "10 days"
        distinctiveAgentMinLength: 30
        
Configurations
--------------

1. The entity manager to use

    entity_manager_login:
        name: ""
        
	You may want to use a different database user for the authentication then for the application itself. 
	Then you do not have to GRANT the user of the default entity manager access to the tables where authentication data is stored. 
	This gives a smaller contact surface wherefrom the sensitive authentication data can be reached.  

	And the user of the authentication entity manager does not need to have access to the tables where the application data is stored.
	This keeps your application data one step further away from the authentication functions that can after all be accessed by everybody. 
 
	So if you have a separate entity manager for authentication, you can pass its name here.

2. Counting duration

	counterDurationInSeconds

	From this setting the Tresholds Governor decides when a new RequestCounts record will be made for the same combination of 
	username, IP address and user agent. The higher you set this, the less records will be generated, thus the faster counting will be. 
	But it needs to be substantially shorter then the blockIpAddressesFor and blockUsernamesFor durations not to get too unprecise countings.
	
3. Username blocking duration
 
	blockUsernamesFor
	
	The duration for which failed logins are countend per username. Values like "3 minutes", "12 hours", "5 years" are allowed.
	
	The OWASP Guide does not advise about a separate lockout duration per user name. 
	Many applications block user accounts forever after three or five attempts. 
	This is not supported, but you may set the duration long. Be aware that the number of counters may have to become
	very high, slowing down the authentication process.

	Counters that start before the system time minus this duration do not count for this purpose.
	However, this does not mean that usernames that became blocked will never be blocked after this duration: if more 
	failed logins where counted afterwards in newer RequestCounts records, these will remain to count while the older
	RequestCounts are no longer counted. As long as the total is higher then limitPerUserName, the username will
	remain blocked, unless it is released*.
	

4. Username blocking theshold

	limitPerUserName
	
	The number of failed login attempts that are allowed per username within the username blocking duration. 
	If the number of failed logins is higher the user will be blocked, unless his failures are released*.
	
5. IP address blocking duration.

	blockIpAddressesFor 
	
	The duration for which failed logins are countend per ip addess. Values like "3 minutes", "12 hours", "5 years" are allowed.
	
	The OWASP Guide suggests a duration of 15 minutes, but also suggests additional measures that are currenly not supported
	by this Bundle. 
	
	Counters that start before the system time minus this duration do not count for this purpose.
	However, this does not mean that addresses that became blocked will never be blocked after this duration: if more 
	failed logins where counted afterwards in newer RequestCounts records, these will remain to count while the older
	RequestCounts are no longer counted. As long as the total is higher then limitPerIpAddress, the addresses will
	remain blocked, unless it is released*.
	
6. IP address blocking treshold
	
	limitBasePerIpAddress
	
	The number of failed login attempts that are allowed per IP address within the IP adress blocking duration. 
	If the number of failed logins is higher the address will be blocked, unless its failures are released*.
	
7. Release user on login success

	releaseUserOnLoginSuccess
	
	Most systems that count failed logins per user account only count the failed logins since the last successfull one.
	If this option is set to true, you get the same result: each time the user logs in sucessfully, the
	username is released for all ip addresses and user agents. And only failures AFTER the last release are counted. 

	This allows slow/distributed attacks to go on for a long period when the user logs in frequently.
	If this option is set to false, user names are only released for the IP address and user agent the
	successfull login was made from. The username may still become blocked for all the other IP addresses 
	and user agents. The disadvantage is that the user will be blocked when his IP address or user agent changes,
	for example because he wants to log in from a different device or connection.

8. Username release duration by IP address

	allowReleasedUserOnAddressFor
	
	For how long a username will remain released per IP address. Values like "3 minutes", "12 hours", "5 years" are allowed.

	If a user logs in frequently this will frequently produce new releases. This allows the user to
	log in from the same IP address even if his username is under constant attack, as long as the attacks 
	do not come from his IP address. However, he may take a vacation and not log in for some weeks or so. 
	This setting basically says how long this vacation may be and still be allowed to
	log in because of his user agent.
	
9. Username release duration by user agent

	allowReleasedUserOnAgentFor

	For how long a username will remain released per IP address. Values like "3 minutes", "12 hours", "5 years" are allowed.

	If a user logs in frequently this will frequently produce new releases. This allows the user to
	log in from the same user agent even if his username is under constant attack, as long as the attacks 
	do not come from with the same user agent string. However, he may take a vacation and not log in for 
	some weeks or so. This setting basically says how long this vacation may be and still be allowed to
	log in because of his user agent.
	
10. User agent distinction length

	distinctiveAgentMinLength
	
	The users browser may pass a short user agent string or none at all.
	User agent strings that are shorter then the number of characters set here will not qualify for username release by user agent. 
	

* releasing is possible for a username in general, an IP address in general, or for the combination of a username with an user agent/ip address.

