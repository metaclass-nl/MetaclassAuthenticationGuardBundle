<?php

/* parts of the code in this file are copied from UsernamePasswordFormAuthenticationListener
 * and thus (c) Fabien Potencier <fabien@symfony.com>, 
 * the rest is (c) MetaClass Groningen.
 */

namespace Metaclass\AuthenticationGuardBundle\Service;

use Metaclass\TresholdsGovernor\Result\Rejection;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\ParameterBagUtils;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\ProviderNotFoundException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Metaclass\TresholdsGovernor\Service\TresholdsGovernor;

/**
 * Service that replaces Symfonies UsernamePasswordFormAuthenticationListener
 * in order to count authentication requests and block them to stop eventual
 * brute force and/or dictionary attacks.
 */
class UsernamePasswordFormAuthenticationGuard extends AbstractAuthenticationListener
{
    /**
     * @var CsrfTokenManagerInterface stored once again because inherited variable is private
     */
    protected $csrfTokenManager;

    /**
     * @var TokenStorageInterface stored once again because inherited variable is private
     */
    protected $myTokenStorage;

    /**
     * @var TresholdsGovernor that does the counting and may decide to block authentication
     */
    protected $governor;

    /**
     * In order to hide execution time differences when authentication is not blocked.
     *
     * @var float How long execution of the authentication process should take
     */
    public $authExecutionSeconds;

    /**
     * @var string pattern for validating the username
     */
    public static $usernamePattern = '/([^\\x20-\\x7E])/u'; //default is to allow all 1 to 1 visible ASCII characters (from space to ~). This excludes CR, LF, Tab , FF. If you want to be able to register e-mail addresses, don't exclude @

    /**
     * @var string|null pattern(s) for validating the password. If not set, usernamePattern is used
     */
    public static $passwordPattern;

    /**
     * {@inheritdoc}
     */
    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfTokenManagerInterface $csrfTokenManager = null)
    {
        parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
                'username_parameter' => '_username',
                'password_parameter' => '_password',
                'csrf_parameter' => '_csrf_token',
                'intention' => 'authenticate',
                'post_only' => true,
        ), $options), $logger, $dispatcher);

        $this->csrfTokenManager = $csrfTokenManager;
        $this->myTokenStorage = $tokenStorage;
    }

    /**
     * Sets the TresholdsGovernor. Used on configuration.
     *
     * @param TresholdsGovernor $governor
     *
     * @return $this
     */
    public function setGovenor(TresholdsGovernor $governor)
    {
        $this->governor = $governor;

        return $this;
    }

    /** Sets the pattern(s) for validating the username and password.
     * May be called on configuration.
     * Defaults are in the declaration of the variables.
     *
     * @param string      $usernamePattern
     * @param string|null $passwordPattern if null the $usernamePattern is also used for validating the password
     */
    public function setValidationPatterns($usernamePattern, $passwordPattern = null)
    {
        self::$usernamePattern = $usernamePattern;
        if ($passwordPattern !== null) {
            self::$passwordPattern = $passwordPattern;
        }
    }

    /**
     * In order to hide execution time differences when authentication is not blocked.
     *
     * @var float How long execution of the authentication process should take
     */
    public function setAuthExecutionSeconds($seconds)
    {
        $this->authExecutionSeconds = $seconds;
    }

    /**
     * {@inheritdoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('POST')) {
            return false;
        }

        return parent::requiresAuthentication($request);
    }

    /**
     * {@inheritdoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        $exception = null;
        $originalCred = $this->getCredentials($request);
        $filteredCred = $this->filterCredentials($originalCred);
        $request->getSession()->set(Security::LAST_USERNAME, $originalCred[0]);

        if (null !== $this->csrfTokenManager) {
            $this->checkCrsfToken($request);
        }

        //initialize the governor so that we can register a failure
        $this->governor->initFor(
                 $request->getClientIp(), $filteredCred[0], $filteredCred[1], '' //cookieToken not yet used (setting and getting cookies NYI)
             );

        if ($originalCred != $filteredCred) { //we can not accept invalid characters
            $this->governor->registerAuthenticationFailure();
            $exception = new BadCredentialsException('Credentials contain invalid character(s)');
        } else {
            $exception = $this->getExceptionOnRejection($this->governor->checkAuthentication()); //may register failure
            if ($exception === null) {
                //not blocked, try to authenticate
                try {
                    $newToken = $this->authenticationManager->authenticate(new UsernamePasswordToken($filteredCred[0], $filteredCred[1], $this->providerKey));

                    //authenticated! No need to hide timing
                    $this->governor->registerAuthenticationSuccess();

                    //when the user goes to the login page without logging out or on reauthentication because of
                    //an InsufficientAuthenticationException there may still be a UsernamePasswordToken
                    $oldToken = $this->myTokenStorage->getToken();
                    if ($oldToken !== null) {
                        $oldUserName = $oldToken instanceof UsernamePasswordToken ? $oldToken->getUserName() : '';

                        if ($newToken instanceof UsernamePasswordToken && trim($newToken->getUserName()) != trim($oldUserName)) {
                            //user has changed without logout, clear session so that the data of the old user can not leak to the new user
                            $request->getSession()->clear();
                        }
                    }

                    return $newToken;
                } catch (AuthenticationException $e) {
                    if ($this->isClientResponsibleFor($e)) {
                        $this->governor->registerAuthenticationFailure();
                    } //else do not register service errors as failures
                    // wait to hide eventual execution time differences
                    if ($this->authExecutionSeconds) {
                        // \Gen::show($this->governor->getSecondsPassedSinceInit()); die();
                        $this->governor->sleepUntilSinceInit($this->authExecutionSeconds);
                    }
                    throw $e;
                }
            }
        } // end $originalCred != $filteredCred

        $this->governor->sleepUntilFixedExecutionTime(); // hides execution time differences of tresholds governor

        throw $exception;
    }

    /** Converts a Rejection from the TresholdsGovernor to an Exception
     * using a naming scheme.
     *
     * @param Rejection $rejection
     *
     * @return \Metaclass\AuthenticationGuardBundle\Exception\AuthenticationBlockedException if a rejection is passed.
     */
    protected function getExceptionOnRejection(Rejection $rejection = null)
    {
        if ($rejection) {
            $exceptionClass = 'Metaclass\\AuthenticationGuardBundle\\Exception\\'
                .subStr(get_class($rejection), 35).'Exception';

            return new $exceptionClass(strtr($rejection->message, $rejection->parameters));
        }
    }

    /** Checks if the csrf_token_id is valid as a CSRF token
     * @param Request $request
     *
     * @throws InvalidCsrfTokenException if it is invalid
     */
    protected function checkCrsfToken(Request $request)
    {
        $csrfToken = ParameterBagUtils::getRequestParameterValue($request, $this->options['csrf_parameter']);

        if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['csrf_token_id'], $csrfToken))) {
            throw new InvalidCsrfTokenException('Invalid CSRF token.');
        }
    }

    /** Get the credentials from the request.
     * @param Request $request
     *
     * @return array with the credentials, username at 0, password at 1 (int)
     */
    protected function getCredentials(Request $request)
    {
        if ($this->options['post_only']) {
            $username = trim($request->request->get($this->options['username_parameter'], null, true));
            $password = $request->request->get($this->options['password_parameter'], null, true);
        } else {
            $username = trim($request->get($this->options['username_parameter'], null, true));
            $password = $request->get($this->options['password_parameter'], null, true);
        }

        return array($username, $password);
    }

    /** Filter the credentials to protect against invalid UTF-8 characters.
     * @param array $usernameAndPassword, username at 0, password at 1 (int)
     *
     * @return array filtered credentials, username at 0, password at 1 (int)
     */
    public static function filterCredentials($usernameAndPassword)
    {
        return array(
            self::filterUsername($usernameAndPassword[0]),
            self::filterPassword($usernameAndPassword[1]),
        );
    }

    /** Filter the username using self::$usernamePattern
     * @param string $value
     *
     * @return string filtered username
     */
    public static function filterUsername($value)
    {
        return preg_replace(self::$usernamePattern, ' ', $value);
    }

    /** Filter the password using self::$passwordPattern if not null, else using self::$usernamePattern
     * @param string $value
     *
     * @return string filtered password
     */
    public static function filterPassword($value)
    {
        return preg_replace((self::$passwordPattern === null ? self::$usernamePattern : self::$passwordPattern), ' ', $value);
    }

    /** Wheather the client (who sended the request) is reponsible for the authentication failure.
     * imho AuthenticationServiceException and ProviderNotFoundException signal bad service plumming,
     * and counting them would only lead to blocking legitimate users.
     *
     * @param AuthenticationException $e
     *
     * @return bool
     */
    public static function isClientResponsibleFor(AuthenticationException $e)
    {
        return !($e instanceof AuthenticationServiceException
                    || $e instanceof ProviderNotFoundException);
    }
}
