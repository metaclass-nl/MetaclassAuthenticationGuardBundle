Authentication Guard for Symfony 2
==================================
 
INTRODUCTION
------------
The OWASP Guide states "Applications MUST protect credentials from common authentication attacks as detailed 
in the Testing Guide". Symfony 2 has a firewall and a series of authentication components, but none to 
protect against brute force and dictionary attacks. This Bundle aims to protect user credentials from 
these authentication attacks. It is based on the "Tresholds Governer" described in the OWASP Guide.

FEATURES
--------

- Blocks the primary authentication route by both username and client ip address for which authentication failed  too often,
 
- To hide weather an account actually exists for a username, any username that is tried too often may be blocked, 
  regardless of the existence and status of an account with that username,

- Makes a logical difference between failed login lockout (done by this bundle) and eventual administrative lockout 
  (may be done by the UserBundle), so that re-enabling all usernames en masse does not unlock administratively locked users
  (OWASP requirement).

- Automatic release of username on authentication success,

- Stores counters instead of individual requests to prevent database flooding from brute force attacks,

REQUIREMENTS
------------
This bundle is for the symfony framework and requires Symfony >=2.6 and <3.0-dev.
(for Symfony ~2.3 use v0.3)
Requires metaclass-nl/tresholds-governor 0.2@dev which uses Doctrine DBAL >=2.3
Tested with MySQL 5.5.

RELEASE NOTES
-------------

This is a pre-release version under development. 

Currently the Bundle can only protect form-based authentication using the security.authentication.listener.form service 
(Default: Symfony\Component\Security\Http\Firewall\UsernamePasswordFormAuthenticationListener).

Throws specific types of Exceptions for different situations (for logging purposes) and leaves it to the
login form to hide differences between them that should not be reported to users.

May be vurnerable to enumeration of usernames through timing attacks because of
differences in database query performance for frequently and infrequently used usernames.
This can be mitigated by calling ::sleepUntilFixedExecutionTime. Under normal circomstances
that should be sufficient if the fixedExecutionSeconds is set long enough, but under
high (database) server loads when performance degrades, under specific conditions
information may still be extractable by timing. Furthermore, the measures against
timing attacks where not tested for practical effectiveness.

The web based administration user interface is experimental and requires doctrine/doctrine-bundle.

DOCUMENTATION
-------------
- [Installation and configuration](Resources/doc/Installation.md)
- [Hooking into Symfony](Resources/doc/Hooking into Symfony.md)
- [Underlying Tresholds Governor library](https://github.com/metaclass-nl/tresholds-governor)
	
SUPPORT
-------

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