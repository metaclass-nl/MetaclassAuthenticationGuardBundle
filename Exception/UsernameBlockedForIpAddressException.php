<?php

namespace Metaclass\AuthenticationGuardBundle\Exception;

/**
 * Thrown if the username has been released less then
 * 'allowReleasedUserOnAddressFor' ago for the ip address the request came from,
 * when authentication is blocked because more requests then configured in
 * 'limitPerUserName' with the username have failed within the time period
 * configured in 'blockUsernamesFor' minus 'counterDurationInSeconds'.
 */
class UsernameBlockedForIpAddressException extends UsernameBlockedException
{
}
