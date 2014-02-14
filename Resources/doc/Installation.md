INSTALLATION AND CONFIGURATION
==============================

Installation
------------

1. Check if you have the following setting in your app/conf/security.yml:
	```yml
	    firewalls:
	        secured_area:
	            form_login: 
	```
	If you have no firewall, there is no authentication to guard. If you have some other setting instead of form_login:,
	for example http_basic:, http_digest: or x509:, the current version of this bundle can not guard it. (remember_me: 
	will usually be combined with some other Authentication Listener, currently this bundle can not guard it)

	If you have a setting like this:
	```yml
	    firewalls:
	        secured_area:
	            form_login:
	            	id: somecustomserviceid 
	```
	you are using a custom form authenticaton listener service. This bundle can only guard it if your service is configured
	to use the default security.authentication.listener.form.class 
	(Symfony\Component\Security\Http\Firewall\UsernamePasswordFormAuthenticationListener)
	and you will have to write your own configuration to use instead of the one under step 4.

2. Require the bundle in your composer.json
	```js
	{
	    "require": {
	        "metaclass-nl/authentication-guard-bundle": "*@dev"
	    }
	}
	```
3. download the bundle by:

	``` bash
	$ php composer.phar update metaclass-nl/authentication-guard-bundle
	```

	Composer will install the bundle to your `vendor/metaclass-nl` folder.

4. Create the database table

	```sql
	CREATE TABLE `secu_requests` (
	  `id` int(11) NOT NULL AUTO_INCREMENT,
	  `dtFrom` datetime NOT NULL,
	  `username` varchar(25) COLLATE utf8_unicode_ci NOT NULL,
	  `ipAddress` varchar(25) COLLATE utf8_unicode_ci NOT NULL,
	  `agent` varchar(255) COLLATE utf8_unicode_ci NOT NULL,
	  `loginsFailed` int(11) NOT NULL,
	  `loginsSucceeded` int(11) NOT NULL,
	  `requestsAuthorized` int(11) NOT NULL,
	  `requestsDenied` int(11) NOT NULL,
	  `userReleasedAt` datetime DEFAULT NULL,
	  `addresReleasedAt` datetime DEFAULT NULL,
	  `userReleasedForAddressAndAgentAt` datetime DEFAULT NULL,
	  PRIMARY KEY (`id`),
	  KEY `byDtFrom` (`dtFrom`),
	  KEY `byUsername` (`username`,`dtFrom`,`userReleasedAt`),
	  KEY `byAddress` (`ipAddress`,`dtFrom`,`addresReleasedAt`),
	  KEY `byUsernameAndAddress` (`username`,`ipAddress`,`dtFrom`,`userReleasedForAddressAndAgentAt`)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci ;
	
	```
	(you may use MyISAM, but processing multiple requests simultanously may result in some (non-fatal) counting race conditions during brute force attacks)
	(you may use some other DBMS that is supported by Doctrine DBAL)

5. Add the bundle to your AppKernel

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

6. Add the following to your app/config/security.yml:

	```yml
    services: 
        security.authentication.listener.form:
            class: %metaclass_auth_guard.authentication.listener.form.class%
            parent: "security.authentication.listener.abstract"
            abstract: true
            calls:
                - [setGovenor, ["@metaclass_auth_guard.tresholds_governor"] ] # REQUIRED
    ```

7. You may also add the following configuraton parameters (defaults shown):

	```yml
metaclass_authentication_guard:
    entity_manager_login:
        name: ""
    tresholds_governor_params:
        counterDurationInSeconds:  300
        blockUsernamesFor: "24 minutes"       # actual blocking for up to counterDurationInSeconds shorter!
        limitPerUserName: 3
        blockIpAddressesFor: "17 minutes"     # actual blocking for up to counterDurationInSeconds shorter!
        limitBasePerIpAddress: 10
        releaseUserOnLoginSuccess: false
        allowReleasedUserOnAddressFor: "30 days" 
        allowReleasedUserOnAgentFor: "10 days"
        distinctiveAgentMinLength: 30
```

8. If you want to run the tests you may add the following to the testsuites section of your app/phpunit.xml:
	```xml
        <testsuite name="MetaclassAUthenticationGuardBundle Test Suite">
            <directory>../vendor/metaclass-nl/authentication-guard-bundle/Metaclass/AuthenticationGuardBundle/Tests</directory>
         </testsuite>
	```
  
Configurations
--------------

1. The entity manager to use

    entity_manager_login:
        name: ""
        
	The default for this setting is emtpy, resulting in the default Entity Manager to be used. 
	If you some specific value a specific entity manager will be used for storing and retieving RequestCounts. 

2. Counting duration

	counterDurationInSeconds

	From this setting the Tresholds Governor decides when a new RequestCounts record will be made for the same combination of 
	username, IP address and user agent. The higher you set this, the less records will be generated, thus the faster counting will be. 
	But it needs to be substantially shorter then the blockIpAddressesFor and blockUsernamesFor durations not to get too unprecise countings.
	
3. Username blocking duration
 
	blockUsernamesFor
	
	The duration for which failed login counters are summed per username. Values like "3 minutes", "12 hours", "5 years" are allowed.
	The actual duration of blocking will be up to 'counterDurationInSeconds' shorter.
	
	The OWASP Guide: 
	> If necessary, such as for compliance with a national security standard, a configurable soft lockout of approximately 15-30 minutes should apply, with an error message stating the reason and when the account will become active again.
	Hoever, many applications block user accounts after three or five attempts until they are reactivated explicitly. 
	This is not supported, but you may set the duration long. Be aware that the number of counters may have to become
	very high, slowing down the authentication process [idea for improvement](https://github.com/metaclass-nl/MetaclassAuthenticationGuardBundle/wiki). 

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
	
	The duration for which failed login counters are summed per ip addess. Values like "3 minutes", "12 hours", "5 years" are allowed.
	The actual duration of blocking will be up to 'counterDurationInSeconds' shorter.
	
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
	
Notes

- releasing is possible for a username in general, an IP address in general, or for the combination of a username with an user agent/ip address

