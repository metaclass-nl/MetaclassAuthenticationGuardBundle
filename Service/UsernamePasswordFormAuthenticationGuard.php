<?php 
/* parts of the code in this file are copied from UsernamePasswordFormAuthenticationListener
 * and thus (c) Fabien Potencier <fabien@symfony.com>, 
 * the rest is (c) MetaClass Groningen.
 */

namespace Metaclass\AuthenticationGuardBundle\Service;

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

class UsernamePasswordFormAuthenticationGuard extends AbstractAuthenticationListener {
    
    protected $csrfTokenManager;
    protected $myTokenStorage;
    
    protected $governor;
    public $authExecutionSeconds;
    static $usernamePattern = '/([^\\x20-\\x7E])/u'; //default is to allow all 1 to 1 visible ASCII characters (from space to ~). This excludes CR, LF, Tab , FF. If you want to be able to register e-mail addresses, don't exclude @
    static $passwordPattern; //if not set, usernamePattern is used
    
    /**
     * {@inheritdoc}
     */
    public function __construct(TokenStorageInterface $tokenStorage, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfTokenManagerInterface $csrfTokenManager = null)
    {
        parent::__construct($tokenStorage, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
                'username_parameter' => '_username',
                'password_parameter' => '_password',
                'csrf_parameter'     => '_csrf_token',
                'intention'          => 'authenticate',
                'post_only'          => true,
        ), $options), $logger, $dispatcher);
    
        $this->csrfTokenManager = $csrfTokenManager;
        $this->myTokenStorage = $tokenStorage;
    }
    
    public function setGovenor(TresholdsGovernor $governor) {
        $this->governor = $governor;
        return $this;
    }
    
    public function setValidationPatterns($usernamePattern, $passwordPattern=null) {
        self::$usernamePattern = $usernamePattern;
        if ($passwordPattern !== null) {
            self::$passwordPattern = $passwordPattern;
        }
    }

    /**
     * In order to hide execution time differences when authentication is not blocked
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
                 $request->getClientIp()
                , $filteredCred[0]
                , $filteredCred[1]
                , '' //cookieToken not yet used (setting and getting cookies NYI)
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
    
    protected function getExceptionOnRejection($rejection)
    {
        if ($rejection) {
            $exceptionClass = 'Metaclass\\AuthenticationGuardBundle\\Exception\\'
                . subStr(get_class($rejection), 35). 'Exception';
            return new $exceptionClass(strtr($rejection->message, $rejection->parameters));
        }
    }
    
    protected function checkCrsfToken(Request $request) 
    {
        $csrfToken = ParameterBagUtils::getRequestParameterValue($request, $this->options['csrf_parameter']);

        if (false === $this->csrfTokenManager->isTokenValid(new CsrfToken($this->options['csrf_token_id'], $csrfToken))) {
            throw new InvalidCsrfTokenException('Invalid CSRF token.');
        }
    }    
    
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
    
    /** Filter the credentials to protect against invalid UTF-8 characters */
    public static function filterCredentials($usernameAndPassword) {
        return array(
            self::filterUsername($usernameAndPassword[0]),
            self::filterPassword($usernameAndPassword[1])
        );
    }

    public static function filterUsername($value)
    {
        return preg_replace(self::$usernamePattern, ' ', $value);
    }

    public static function filterPassword($value)
    {
        return preg_replace( (self::$passwordPattern === null ? self::$usernamePattern : self::$passwordPattern), ' ', $value);
    }
    
    static public function isClientResponsibleFor(AuthenticationException $e) {
        //imho AuthenticationServiceException and ProviderNotFoundException signal bad service plumming
        return !($e instanceOf AuthenticationServiceException 
                    || $e instanceOf ProviderNotFoundException);
    }
}
?>