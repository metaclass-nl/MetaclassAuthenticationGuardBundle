Counting and deciding
=====================

The Guard reports login results to the TesholdsGovernor service and asks it to decide wheather to allow another 
login attempt. The TresholdsGovernor only interacts with the database
through the RequestCountsRepository, but for readability this document does as if it does the database work itself.

Counting
--------

The TesholdsGovernor could simply add a record for each login request and count them later, but then when the site
would be under a brute force attack, it would have to create and count many records. This could slow down the site
consideraby and use up a lot of permanent storage space. Instead it creates records with counters that are
incremented for some time. 

The TesholdsGovernor inserts a record in the RequestCounts table for each unique combination of username, IP address and
user agent. The record holds a counter for the number of logins that succeeded and another for the number of logins that failed.
The counter that corresponds to the login result is initially set to one, the other to zero. 

If another login request is received from the same IP address and user agent for the same username, the existing
RequestCounts records counter that corresponds to the login result is incremented, unless it has been released 
(see under Releasing).

In order to distinguish between new and old login attempts, each RequestCounts record has a DateTime field 'dtFrom'.
Time is devided into periods of equal duration, starting at UNIX epoch. The duration is set in the configuration
parameter 'counterDurationInSeconds'. The dtFrom field is set to the start of the current period at record creation time. 
Counters of existing records are only incremented during the same counting period. After the start of a new counting
period a new record is created on the receival of a login request.

To simplify things, it is advisable to set 'counterDurationInSeconds' to a value by which a day or an hour can be devided. 
For example if you set it to 3 minutes, the first counter period of a day will start at 00:00:00, 
the second at, 00:03:00, the third at 00:06:00, and so on until 00:57:00. Then everyting will be repeated for the
next hour, the next day etc. So if a login request is received with some combination of IP address, user agent and username
at 00:02:23 the TresholdsGovernor will look for a record with dtFrom 00:00:00. If another login request is received 
at 00:02:57 from the same IP address and user agent for the same username, a counter from record previously made
with dtFrom 00:00:00 is incremented. But if anouther login request is received at 00:03:01, a new record is created
with dtFrom 00:03:00.

When the TresholdsGovernor is initialized it adds up all 'loginsFailed' counters from all records with the 
IP address that the request is coming from that are less old then the 'blockIpAddressesFor' setting duration [idea for improvement](https://github.com/metaclass-nl/MetaclassAuthenticationGuardBundle/wiki/Home). 
Counters from records whose IP address has been released are not added. The same is done for the username from 
the request, but with the settings 'blockUsernamesFor' and not adding counter whose username has been released. 

The total is higher then the 'limitBasePerIpAddress' setting, the login attempt will be blocked, unless the 
a release is registered (This will be explained under 'releasing'). The same is done for the username from the request,  
but with the settings 'blockUsernamesFor' and 'limitPerUserName'.

Releasing
---------

When a username or IP address has become blocked, legimite users may not want to wait until the blocking 
period has passed. To unblock them the TresholdsGovernor can set the 'userReleasedAt' field in the RequestsCounts 
records with a username to the DateTime of the release, or the 'addresReleasedAt' field in the records with an IP address. 
It will only set the released field of RequestCounts whose dtFrom is less then the 'blockUsernamesFor' respectively 
'blockIpAddressesFor' setting duration ago, and only where the field setted is null.

When a users username is under attack, it may soone become blocked again. To allow the user in while still 
protecting against the attack, a username may be released *only* for an IP address and user agent. The  
TresholdsGovernor then sets the DateTime of the release to the userReleasedForAddressAndAgentAt of all
RequestCounts records whose dtFrom is less then the 'blockUsernamesFor' setting duration ago and whose 
IP address or user name matches one of the specified. 

Most systems that count failed logins per user reset the failed logins counter when a login is successfull.
If the 'releaseUserOnLoginSuccess' option is set to true, you get the same result: each time the user logs in sucessfully, 
the username is released (setting the 'userReleasedAt' field). And only failures from unreleased records are added to 
the total. 

This allows slow/distributed attacks to go on for a long period when the user logs in frequently.
If the 'releaseUserOnLoginSuccess' option is set to false, user names are only released for the IP address and 
user agent the successfull login was made from (setting the 'userReleasedForAddressAndAgentAt' field). 
The username may stay or become blocked for all the other IP addresses and user agents. 
The disadvantage is that the may be blocked when his IP address or user agent changes,
for example because he wants to log in from a different device or connection.


Deciding
--------

When the TresholdsGovernor is asked to check an authentication, it compares the totals that where calculated
wen it was initialized (see under 'Counting') with the limits from the settings. If the number of failures 
per IP address is higher then the 'limitBasePerIpAddress' setting, it will throw an IpAddressBlockedException. 
If the number of failures per username is higer hten the 'limitPerUserName' setting, it will throw a 
UsernameBlockedException.

A special case is made for when the username has been released for the IP address or user agent the
login is made from, but only when the last release is less then the 'blockUsernamesFor' setting duration ago.
If the user has been released on the IP address, only failures are added that are made from the same IP address. 
If the total is higher then the 'limitPerUserName' setting, it will throw a UsernameBlockedForIpAddressException.
If the user has been released for the user agent (but not on the IP address), only failures are added that are 
made from the same user agent**. If the total is higher then the  'limitPerUserName' setting, it will throw 
UsernameBlockedForAgentException.

All these exceptions inherit from AuthenticationBlockedException. 

Improvements
------------
Ideas for improvements are duscussed [on the wiki](https://github.com/metaclass-nl/MetaclassAuthenticationGuardBundle/wiki)