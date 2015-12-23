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

2. Require the bundle and the tresholds governor library it needs in your composer.json
	```js
	{
	    "require": {
	        "metaclass-nl/authentication-guard-bundle": "*@dev",
	        "metaclass-nl/tresholds-governor":  "*@dev"
	    }
	}
	```
3. download the bundles by:

	``` bash
	$ php composer.phar update metaclass-nl/authentication-guard-bundle
	$ php composer.phar update "metaclass-nl/tresholds-governor
	```

	Composer will install the bundle and library in your `vendor/metaclass-nl` folder.

4. Create the database table

	See step 3 of the Install documentation of the [tresholds-governor]((https://github.com/metaclass-nl/tresholds-governor/)

5. Add the bundle to your AppKernel

	``` php
	<?php
	// app/AppKernel.php
	
	public function registerBundles()
	{
	    $bundles = array(
	        // ...
	        new Metaclass\AuthenticationGuardBundle\MetaclassAuthenticationGuardBundle(),
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
                - [setAuthExecutionSeconds, [0.99]] # voluntary
    ```

7. You may also add the following configuraton parameters (defaults shown):

	```yml
    metaclass_authentication_guard:
        db_connection:
            name: "default"
        tresholds_governor_params:
            counterDurationInSeconds:  300
            blockUsernamesFor: "24 minutes"       # actual blocking for up to counterDurationInSeconds shorter!
            limitPerUserName: 3
            blockIpAddressesFor: "17 minutes"     # actual blocking for up to counterDurationInSeconds shorter!
            limitBasePerIpAddress: 10
            releaseUserOnLoginSuccess: false
            allowReleasedUserOnAddressFor: "30 days"
            keepCountsFor: "4 days"
            fixedExecutionSeconds: "0.1"
            randomSleepingNanosecondsMax: 99999
        ui:
            dateTimeFormat: "SHORT"
    ```

8. From cron or so you may garbage-collect/pack stored RequestCounts:
	```php
    require_once 'app/AppKernel.php';

    $kernel = new AppKernel('prod', false); //for production environment. You may change 'prod' for other environments
    $kernel->loadClassCache();
    $kernel->boot();
    $container = $kernel->getContainer();

    $governor = $container->get('metaclass_auth_guard.tresholds_governor');
    $result = $governor->packData();

    //if you want to log the result:
    $secuLogger = $container->get('monolog.logger.security');
    $secuLogger->info('tresholds_governor deleted requestcounts until '. $result["requestcounts_deleted_until"]->format('Y-m-d H:m:s') );
    $secuLogger->info('tresholds_governor deleted releases until '. $result["releases_deleted_until"]->format('Y-m-d H:m:s') );

    ```

9. The user interface for user administrators to look into why a user may have been blocked is experimental and its labels are still in Dutch.
    If you want enable it, add the following to your app/config/routing.yml:
    ```yml
    	metaclass_auth_guard:
            resource: "@MetaclassAuthenticationGuardBundle/Resources/config/routing.yml"
            prefix:   /
    ```
     And add the path of the user interface to your firewall in app/conf/security.yml:
    ```yml
        access_control:
            - { path: ^/guard, roles: ROLE_ADMIN }
    ```
     (there will probably already be an access_control configuration with several paths listed.
     Add the above path to the list in an appropriate place. You may have to adapt ROLE_ADMIN to the user role identifier
     appropriate for your application's security configuration.

     The user interface has the following entries:
     - guard/statistics
     - guard/history/ipAddress (replace 'ipAddress' by an actual ip address)
     - guard/statistics/username (replace 'username' by an actual username)

     The default template assumes you have base.html.twig still in app/Resources/views.
     In an actual application you typically use a template of your own that extends your own layout
     and includes MetaclassAuthenticationGuardBundle:Guard:statistics_content.html.twig .
     To change the template used override the parameter metaclass_auth_guard.statistics.template
     in your applications configuration.

     If your layout requires more parameters you probably want to use your own subclass
     of GuardStatsController. For this you may override the route(s) from Resources/config/routing.yml
     in your applications routing.yml after the metaclass_auth_guard resource configuration
     or replace the resource configuration entirely.

     If you want to use other datetime widgets you may override the parameter
     metaclass_auth_guard.statistics.StatsPeriod.formType to refer to a class of your own.

     Currently the web based user interface only supports English and Dutch.
     Please clone the Bundle on Github and add your own language translation!

10. If you want to run the tests you may add the following to the testsuites section of your app/phpunit.xml:
	```xml
        <testsuite name="MetaclassAUthenticationGuardBundle Test Suite">
            <directory>../vendor/metaclass-nl/authentication-guard-bundle/Metaclass/AuthenticationGuardBundle/Tests</directory>
         </testsuite>
	```
  
Configurations
--------------

1. The database connection to use

    db_connection:
        name: ""
        
	The default for this setting is emtpy, resulting in the default doctrine dbal connection to be used. 
	If you specify some specific value a specific connection will be used for storing and retieving RequestCounts data. 

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

9. Garbage collection delay

    keepCountsFor

    For how long the requestcounts will be kept before being garbage-collected. Values like "4 days".

    If you have enabled the user interface for user administrators to look into why
    a user may have been blocked, this is how long they can look back in time to see
    what happened.

    This value must allways be set longer then both blockUsernamesFor and blockIpAddressesFor,
    otherwise counters will be deleted before blocking should end and no longer be counted in
    for blocking.

    Currently the user interface shows no information about active releases, but for
    future extension this value also acts as a minimum for how long releases will be kept before being
    garbage collected, but if allowReleasedUserOnAddressFor (or allowReleasedUserByCookieFor)
    is set to a longer duration, the releases will be kept longer (according to the longest one).

10. Fixed execution time

    fixedExecutionSeconds

    Fixed execution time in order to mitigate timing attacks. To apply, call ::sleepUntilFixedExecutionTime.

11. Maximum random sleeping time in nanoseconds

    randomSleepingNanosecondsMax

    Because of doubts about the accurateness of microtime() and to hide system clock
    details a random between 0 and this value is added by ::sleepUntilSinceInit (which
    is called by ::sleepUntilFixedExecutionTime).

12.
    ui:
        dateTimeFormat

    \IntlDateFormatter pattern or datetype. If a dattype is set
    (FULL, LONG, MEDIUM or SHORT) (case independent) the corresponding
    dateformat is used and no pattern so that the formatting will depend
    on the locale. Otherwise the parameter is used as pattern with
    \Symfony\Component\Form\Extension\Core\Type\DateTimeType::DEFAULT_DATE_FORMAT
    as datetype. As timetype DateTimeType::DEFAULT_TIME_FORMAT allways used so that
    the formatting is the same as done by the DateTimeType widgets in the Period form.

    If you need specific patterns for different locales you may use your own subclass
    of GuardStatsController and override ::initDateFormatAndPattern to set the appropriate
    datetype and format, or override ::initDateTimeTransformer to set whatever
    transformer you may like (but that will not be used by the DateTimeType widgets in the
    Period form so you may want to set your own form type too).

Notes

- releasing is possible for a username in general, an IP address in general, or for the combination of a username with an ip address

