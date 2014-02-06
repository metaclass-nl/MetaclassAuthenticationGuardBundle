Hooking into Symfony
====================

Authentication Listener service
-------------------------------

To acticate the Guard the following setting replaces the default security.authentication.listener.form service:

services: 
    security.authentication.listener.form:
        class: %metaclass_auth_guard.authentication.listener.form.class%
        parent: "security.authentication.listener.abstract"
        abstract: true
        calls:
            - [setGovenor, ["@metaclass_auth_guard.tresholds_governor"] ] # REQUIRED

Instead of an instance of Symfony\Component\Security\Http\Firewall\UsernamePasswordFormAuthenticationListener
the service will be an instance of Metaclass\AuthenticationGuardBundle\Service\UsernamePasswordFormAuthenticationGuard.

Just like UsernamePasswordFormAuthenticationListener, UsernamePasswordFormAuthenticationGuard extends
Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener.  Furthermore, some of its code
was copied from UsernamePasswordFormAuthenticationListener. The reason UsernamePasswordFormAuthenticationListener
was not extended is that it makes some properties private that are needed by the Guard, and that 
refactoring was needed so that only one small method could be inherited. 

This is where UsernamePasswordFormAuthenticationGuard is different:
1. It requires access to a TressholdsGovernor
2. Sanitizes the credentials to protect against invalid UTF-8 characters
3. It initializes the TressholdsGovernor,
4. If the credentials did contain unwanted characters, it registers an authentication failure with the TressholdsGovernor 
   and throws a BadCredentialsException,
5. It lets the TressholdsGovernor check the authentication attempt. (If it rejects the attempt, the TressholdsGovernor
   will throw some sort of AuthenticationBlockedException)
6. If the Authentication Manager throws an AuthenticationException it will check if the user is to be held responsable 
   for the exception. If so, it registers an authentication failure with the TressholdsGovernor before it rethrows 
   the Exception. (imho AuthenticationServiceException and ProviderNotFoundException signal bad service plumming
   for which the user should not be blocked later when the problem is solved).
7. If the Authentication Manager does not throw an AuthenticationException it registers an authentication success with the 
   TressholdsGovernor.
8. If there still is a old UsernamePasswordToken in the session, and the Authentication Manager has returned a new 
   UsernamePasswordToken with a different user name, the session is cleared in order to prevent session data from
   the old user to leak to the new user*.
   

Doctrine ORM Entity Manager
---------------------------
 
You may want to use a different database user for the authentication then for the application itself. 
Then you do not have to GRANT the user of the default entity manager access to the tables where authentication data is stored. 
This gives a smaller contact surface wherefrom the sensitive authentication data can be reached.  

And the user of the authentication entity manager does not need to have access to the tables where the application data is stored.
This keeps your application data one step further away from the authentication functions that can after all be accessed by everybody. 
 
To allow this a specific Entity Manager service is used by the Tresholds Governor. Its Entity Manager name can
be speficfied by the setting:
```yml
    entity_manager_login:
        name: ""
```
 The default for this setting is emtpy, resulting in the default Entity Manager to be used.
 
Alternatives
------------
Ideas for alternatives are discussed [on the wiki](https://github.com/metaclass-nl/MetaclassAuthenticationGuardBundle/wiki/Other-options-for-hooking-the-Guard-into-Symfony%27s-authentication)

 
* ISSUE: Maybe this should be done by the session strategy, not by the Authentication Listener?