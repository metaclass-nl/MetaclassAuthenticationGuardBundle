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
 

Other options explored
----------------------

It is hard to make out which service is intended to do things like registering  
Disadvantage of replacing the security.authentication.listener.form service is that it only works for
form-based authentication. Other options where:

1. Replacing the security.authentication.manager service (AuthenticationProviderManager). 
  The problem with this is that this service has no access to the request. 
  Therefore it does not know the IP address of the login request. 
   
2. Replacing the security.authentication.provider.dao (DaoAuthenticationProvider) service. 
   Also has no access to the request. Would probably not work with non-database providers like with one for
   Ldap, but neither would the current solution.

3. Replacing the AuthenticationFailureHandler and the AuthenticationSuccessHandler. This is not a good place for blocking, 
   because attackers will still get the code executed that retieves the user and checks the password. Timing will then leak the (non)existence of 
   the user, even if the login is blocked later by one of these handlers. 
   Successes and faulures may be registered from here, but the primary goal of these services is deciding on where to
   redirect to after the login has been processed. Developers may therefore want to replace these services too,
   and that would then not be compatible with this bundle.  
   
4. Replacing the UserChecker service. ::checkPreAuth could block attempts before the user is retrieved and the password 
   ckecked, but once again there is no access to the request. And this service too is a likely candidate for
   application developers to replace, also leading to incompatibilty.
 
5. Adding a specific kernel event listener for kernel.request events. This seems to be a good option as none of
   the standard authentication services would have to be replaced, leaving all options open to the application
   developer. The request is available as well, so we know the ip addres. However, the user name would also
   be in the request, but where depends on the security.authentication.listener.form option settings, or if
   a different type of Authentication Listener is used, like BasicAuthenticationListener, it would depend
   on the specifics of that type. Furthermore, the login requests are diverted in an early stage,
   but that may be solved by setting priority lower then 128 (not tested).
   Finally we would need some other service to catch and store authentication results. 
   
6. Adding a specific kernel event listener for kernel.response events. Maybe login results could be cought from there,
   but there will certainly be differences depending on the type of Authentication Listener. 
   
7. Replacing the security.exception_listener service. The login handling starts with a security exception
   that is thrown becuase the login route is protected by the firewall, so it will certaily pass here. The reques
   is available too, Exceptions form the authentication can be caught and the results inferred from them. 
   But the existing exception handling code is probably very important and not very transparent so maintenance
   may become a problem. And we still have the problem of obtaining the user name. 
   Furthermore there is a Cookbook page about changing the target path behavior so application 
   developers may want to replace this service too. 

Basically the disadvantage of having to develop different Guard classes for different kinds of authentication
is only solved by options 1 and 2. Maybe a service could be injected that does have access to the current request.

 
* ISSUE: Maybe this should be done by the session strategy, not by the Authentication Listener?