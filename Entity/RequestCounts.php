<?php

namespace Metaclass\AuthenticationGuardBundle\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\Entity(repositoryClass="RequestCountsRepository")
 * @ORM\Table(name="secu_requests")
 */
class RequestCounts
{
    /**
     * @ORM\Column(type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;
    
    /**
     * @ORM\Column(type="datetime")
     */
    protected $dtFrom;
    
    /**
     * @ORM\Column(type="string", length=25)
     */
    protected $username;
    
    /**
     * @ORM\Column(type="string", length=25)
     */
    protected $ipAddress;
    
    /** last HTTP_USER_AGENT whose login was successull
     * @ORM\Column(type="string", length=255)
     */
    protected $agent = '';
    
    /**
     * @ORM\Column(type="integer")
    */
    protected $loginsFailed = 0;
    
    /**
     * @ORM\Column(type="integer")
     */
    protected $loginsSucceeded = 0;
    
    /**
     * @ORM\Column(type="integer")
     */
    protected $requestsAuthorized = 0;
    
    /**
     * @ORM\Column(type="integer")
     */
    protected $requestsDenied = 0;
    
    /**
     * @ORM\Column(type="datetime", nullable=true)
     */
    protected $userReleasedAt;
    
    /**
     * @ORM\Column(type="datetime", nullable=true)
     */
    protected $addresReleasedAt;
    
    /**
     * @ORM\Column(type="datetime", nullable=true)
     */
    protected $userReleasedForAddressAndAgentAt;

    /**
     * Get id
     *
     * @return integer 
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set date
     *
     * @param \DateTime $date
     * @return Requests
     */
    public function setDtFrom($dateTime)
    {
        $this->dtFrom = $dateTime;
    
        return $this;
    }

    /**
     * Get dtFrom
     *
     * @return \DateTime 
     */
    public function getDtFrom()
    {
        return $this->dtFrom;
    }

    /**
     * Set username
     *
     * @param string $username
     * @return Requests
     */
    public function setUsername($username)
    {
        $this->username = $username;
    
        return $this;
    }

    /**
     * Get username
     *
     * @return string 
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Set ipAddress
     *
     * @param string $ipAddress
     * @return Requests
     */
    public function setIpAddress($ipAddress)
    {
        $this->ipAddress = $ipAddress;
    
        return $this;
    }

    /**
     * Get ipAddress
     *
     * @return string 
     */
    public function getIpAddress()
    {
        return $this->ipAddress;
    }

    /**
     * Set agent
     *
     * @param string $agent
     * @return Requests
     */
    public function setAgent($agent)
    {
        $this->agent = $agent;
    
        return $this;
    }

    /**
     * Get agent
     *
     * @return string 
     */
    public function getAgent()
    {
        return $this->agent;
    }

    /**
     * Set loginsFailed
     *
     * @param integer $loginsFailed
     * @return Requests
     */
    public function setLoginsFailed($loginsFailed)
    {
        $this->loginsFailed = $loginsFailed;
    
        return $this;
    }

    /**
     * Get loginsFailed
     *
     * @return integer 
     */
    public function getLoginsFailed()
    {
        return $this->loginsFailed;
    }

    /**
     * Set loginsSucceeded
     *
     * @param integer $loginsSucceeded
     * @return Requests
     */
    public function setLoginsSucceeded($loginsSucceeded)
    {
        $this->loginsSucceeded = $loginsSucceeded;
    
        return $this;
    }

    /**
     * Get loginsSucceeded
     *
     * @return integer 
     */
    public function getLoginsSucceeded()
    {
        return $this->loginsSucceeded;
    }

    /**
     * Set requestsAuthorized
     *
     * @param integer $requestsAuthorized
     * @return Requests
     */
    public function setRequestsAuthorized($requestsAuthorized)
    {
        $this->requestsAuthorized = $requestsAuthorized;
    
        return $this;
    }

    /**
     * Get requestsAuthorized
     *
     * @return integer 
     */
    public function getRequestsAuthorized()
    {
        return $this->requestsAuthorized;
    }

    /**
     * Set requestsDenied
     *
     * @param integer $requestsDenied
     * @return Requests
     */
    public function setRequestsDenied($requestsDenied)
    {
        $this->requestsDenied = $requestsDenied;
    
        return $this;
    }

    /**
     * Get requestsDenied
     *
     * @return integer 
     */
    public function getRequestsDenied()
    {
        return $this->requestsDenied;
    }
}
