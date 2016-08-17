<?php 
namespace Metaclass\AuthenticationGuardBundle\Exception;

/**
 * Not used.
 *
 * Would be thrown if the username has been released less then
 * 'allowReleasedUserByCookieFor' ago for the cookie used with the request,
 * when authentication is blocked because more requests then
 * configured in 'limitPerUserName' with the username have failed within the
 * time period confiugured in 'blockUsernamesFor' minus 'counterDurationInSeconds'.
 */
class UsernameBlockedForCookieException extends UsernameBlockedException {

}
?>