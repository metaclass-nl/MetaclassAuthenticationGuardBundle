Authentication Guard for Symfony 2
==================================
 
INTRODUCTION
------------

This Bundle aims to protect user credentials from some common authentication attacks:
- Brute force and dictionary attacks trying to obtain valid combinations of username and password. 
- Timming attacks to obtain valid usernames (Symfony 2.2 and up do already protect passwords against timing attacks)

To do so it blocks the primary authentication route for requests with a user name or from a client ip address for which authentication failed  too often. It is based on the "Tresholds Governer" described in the OWASP Guide. To hide wheater an account actually exists for a user name, it will block any user name that is tried too often, regardless of the existence and status of an account with that username.

REQUIREMENTS
------------
This bundle is for the symfony framework and requires Symfony ~2.3 and PHP >=5.3.3
Uses Doctrine >=2.2.3 and was tested with MySQL 5.5.

LIMITATIONS
-----------
Currently the Bundle can only protect form-based authentication using the security.authentication.listener.form service 
(Default: Symfony\Component\Security\Http\Firewall\UsernamePasswordFormAuthenticationListener).

Protection of usernames against timing attacks is probably not fully effective because of:
- differences in database query performance for frequently and infrequently used usernames,
- differences in the execution paths of Symfony's components for existing and non-existing user names.

Does not protect:
- account registration processes (if any)
- password change route (if any)
- password reset route (if any)

Does not enforce timeouts after individual failed login attempts.

Does not monitor the total number of failed authentication attempts per minute, and has no threshold above which the authentication system automatically injects a configurable 45+ second delay between authentication attempts.

Does not protect against many usernames and same password attacks.

Throws specific types of Exceptions for different situations (for logging purposes) and leaves it to the login form to hyde differences between them that should not be reported to users.

Does not garbage-collect nor pack stored RequestCounts. 

Does not contain (examples of) Controllers, forms and entities for 
- sending explanatory e-mails with username and IP adrress release links and tokens
- storing release tokens sent by e-mail
- release username, IP addres, or the combination of username with IP adress or user agent

INSTALLATION AND CONFIGURATION
------------------------------

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

Add the following to your app/config/security.yml:

parameters:
    security.user_checker.class: Metaclass\AuthenticationGuardBundle\Service\UserChecker

services: 
    security.authentication.listener.form:
        class: %metaclass_auth_guard.authentication.listener.form.class%
        parent: "security.authentication.listener.abstract"
        abstract: true
        calls:
            - [setGovenor, ["@metaclass_auth_guard.authentication_governor"] ] # REQUIRED

You may also add the following configuraton parameters :

metaclass_authentication_guard:
    entity_manager_login:
        name: ""
    tresholds_governor_params:
        counterDurationInSeconds:  300
        blockUsernamesFor: "10 days" 
        limitPerUserName: 3
        blockIpAddressesFor: "15 minutes"
        limitBasePerIpAddress: 10
        allowReleasedUserOnAddressFor: "30 days"
        allowReleasedUserOnAgentFor: "10 days"
        releaseUserOnLoginSuccess: false
        distinctiveAgentMinLength: 30
		
RELEASE NOTES
-------------

This is a development version. 
   
SUPPORT
---------------

MetaClass offers help and support on a commercial basis with 
the application and extension of this bundle and additional 
security measures.

http://www.metaclass.nl/site/index_php/Menu/10/Contact.html


COPYRIGHT AND LICENCE
---------------------

Unless notified otherwise Copyright (c) 2014 MetaClass Groningen 

This bundle is under the MIT license. See the complete license in the bundle:

	Resources/meta/LICENSE

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.