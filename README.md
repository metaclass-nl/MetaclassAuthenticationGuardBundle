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
 
- To hide wheater an account actually exists for a user name, any user name that is tried too often may be blocked, regardless of the existence and 
status of an account with that username,

- Makes a logical difference between failed login lockout (done by this bundle) and eventual administrative lockout 
  (may be done by the UserBundle), so that re-enabling all usernames en masse does not unlock administratively locked users.

- Automatic release of username on authentication success,

- Stores counters instead of individual requests to prevent database flooding from brute force attacks.

REQUIREMENTS
------------
This bundle is for the symfony framework and requires Symfony ~2.3 and PHP >=5.3.3
Uses Doctrine >=2.2.3 and was tested with MySQL 5.5.

RELEASE NOTES
-------------

This is a pre-release version under development. 

Currently the Bundle can only protect form-based authentication using the security.authentication.listener.form service 
(Default: Symfony\Component\Security\Http\Firewall\UsernamePasswordFormAuthenticationListener).

May be vurnerable to user enumeration through timing attacks because of differences in database query performance 
for frequently and infrequently used usernames,

Throws specific types of Exceptions for different situations (for logging purposes) and leaves it to the 
login form to hyde differences between them that should not be reported to users.

Does not garbage-collect nor pack stored RequestCounts. 

Unit tests of the TresholdGovernor class are included, but only run from a UnitTestController (not included in the bundle).

DOCUMENTATION
-------------
- [Installation and configuration](Resources/doc/Installation.md)
- [Counting and deciding](Resources/doc/Counting and deciding.md)
- [Hooking into Symfony](Resources/doc/Hooking into Symfony.md)
	
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