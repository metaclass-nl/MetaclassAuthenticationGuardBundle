<?php
// Copyright (c) MetaClass Groningen 2014

namespace Metaclass\AuthenticationGuardBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\Form\Extension\Core\DataTransformer\DateTimeToLocalizedStringTransformer;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Method;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Template;

use Metaclass\AuthenticationGuardBundle\Service\UsernamePasswordFormAuthenticationGuard;
use Metaclass\AuthenticationGuardBundle\Form\Type\StatsPeriodType;

class GuardStatsController extends Controller {

    protected $dtTransformer;

    // #TODO: use translation, maybe use configuration of controller as a service?
    protected $dateTimeFormat = "dd-MM-yyyy HH:mm:ss";
    protected $booleanLabels = array('Nee', 'Ja');
    protected $blockedLabels = array('OK', 'Geblokkeerd');
    protected $rejectionLabels = array(
        'UsernameBlocked' => 'Gebruikersnaam',
        'IpAddressBlocked' => 'Adres',
        'UsernameBlockedForIpAddress' => 'Gebruikersnaam op adres',
    );

    public function __construct()
    {
        $this->dtTransformer = new DateTimeToLocalizedStringTransformer(
            null, null, null, null, \IntlDateFormatter::GREGORIAN, $this->dateTimeFormat);
    }

    /**
     * @Route("/statistics", name="Guard_statistics")
     */
    public function statisticsAction()
    {
        $governor = $this->get('metaclass_auth_guard.tresholds_governor');

        $params['routes']['this'] = 'Guard_statistics';
        $params['labels'] = array('show' => 'Bekijken');
        $params['action_params'] = array();

        $this->addStatisticCommonParams($params, $governor);
        $countingSince = $governor->getMinBlockingLimit();
        $fieldValues =& $params['fieldValues'];
        $fieldValues['countingSince'] = $this->dtTransformer->transform($countingSince);
        $fieldValues['failureCount'] = $governor->requestCountsManager->countLoginsFailed($countingSince);
        $fieldValues['successCount'] = $governor->requestCountsManager->countLoginsSucceeded($countingSince);

        $limitFrom = $this->getRequest()->isMethod('POST')
            ? null
            : $countingSince;
        $limits = $this->addStatsPeriodForm($params, $governor, 'IP Adressen', $limitFrom);

        if (isSet($limits['From'])) {
            $this->addCountsGroupedTableParams($params, $governor, $limits);
            $params['blockedHeaderIndent'] = 6;
            $params['route_history'] = 'Guard_history';
            $params['limits']['From'] = $this->dtTransformer->transform($limits['From']);
            $params['limits']['Until'] = $this->dtTransformer->transform($limits['Until']);
        }
        // #TODO: make params testable
        return $this->render(
            $this->container->getParameter('metaclass_auth_guard.statistics.template'),
            $params);
    }

    /**
     * @Route("/history/{ipAddress}", name="Guard_history", requirements={"ipAddress" = "[^/]+"})
     */
    public function historyAction($ipAddress)
    {
        $governor = $this->get('metaclass_auth_guard.tresholds_governor');

        $params['routes']['this'] = 'Guard_history';
        $params['action_params'] = array('ipAddress' => $ipAddress);
        $params['title'] = 'Inloghistorie';
        $this->buildMenu($params, 'Guard_history');
        $params['fieldSpec'] = array(
            'IP Adres' => 'ipAddress',
            'Maximum per gebruikersnaam' => 'limitPerUserName',
            'Maximum per Adres' => 'limitBasePerIpAddress',
        );
        $params['fieldValues'] = array(
            'ipAddress' => $ipAddress,
            'limitPerUserName' => $governor->limitPerUserName,
            'limitBasePerIpAddress' => $governor->limitBasePerIpAddress,
            );

        $limits = $this->addStatsPeriodForm($params, $governor, 'Historie');

        if (isSet($limits['From'])) {
            $history = $governor->requestCountsManager->countsByAddressBetween($ipAddress, $limits['From'], $limits['Until']);
            $this->addHistoryTableParams($params, $history, 'username', 'Naam');
            $params['route_byUsername'] = 'Guard_statisticsByUserName';
            $params['labels'] = array('show' => 'Bekijken');
            $params['limits']['From'] = $this->dtTransformer->transform($limits['From']);
            $params['limits']['Until'] = $this->dtTransformer->transform($limits['Until']);
        }
        // #TODO: make params testable
        return $this->render(
            $this->container->getParameter('metaclass_auth_guard.statistics.template'),
            $params);
    }
        /**
     * @Route("/statistics/{username}", name="Guard_statisticsByUserName", requirements={"username" = "[^/]*"})
     */
     public function statisticsByUserNameAction($username)
    {
        if (strLen($username) > 25) {
            throw new \BadMethodCallException('Username longer then 25 bytes');
        }
        $filtered = UsernamePasswordFormAuthenticationGuard::filterCredentials(array($username, ''));
        $username = $filtered[0];
        $governor = $this->get('metaclass_auth_guard.tresholds_governor');

        $params['routes']['this'] = 'Guard_statisticsByUserName';
        $params['action_params'] = array('username' => $username);
        $params['fieldSpec'] = array('Gebruikersnaam' => 'username');

        $this->addStatisticCommonParams($params, $governor, 'Guard_statisticsByUserName');

        $params['fieldSpec']['gebruikersnaam op adres vrijgeven voor'] = 'allowReleasedUserOnAddressFor';
        $params['fieldSpec']['Gebruikersnaam geblokkeerd'] = 'usernameBlocked';

        $countingSince = new \DateTime("$governor->dtString - $governor->blockUsernamesFor");
        $fieldValues =& $params['fieldValues'];
        $fieldValues['username'] = $username;
        $fieldValues['countingSince'] = $this->dtTransformer->transform($countingSince);
        $fieldValues['failureCount'] = $governor->requestCountsManager->countLoginsFailedForUserName($username, $countingSince);
        $fieldValues['successCount'] = $governor->requestCountsManager->countLoginsSucceededForUserName($username,$countingSince);
        $isUsernameBlocked = $fieldValues['failureCount'] >= $governor->limitPerUserName;
        $fieldValues['usernameBlocked'] = $this->booleanLabels[$isUsernameBlocked];
        $fieldValues['allowReleasedUserOnAddressFor'] = $this->translatePeriod($governor->allowReleasedUserOnAddressFor);


        $limitFrom = $this->getRequest()->isMethod('POST') || $this->getRequest()->get('StatsPeriod')
            ? null
            : $countingSince;
        $limits = $this->addStatsPeriodForm($params, $governor, 'Historie', $limitFrom);
        if (isSet($limits['From'])) {
            $params['labels'] = array('show' => 'Bekijken');
            $params['route_history'] = 'Guard_history';
            $params['limits']['From'] = $this->dtTransformer->transform($limits['From']);
            $params['limits']['Until'] = $this->dtTransformer->transform($limits['Until']);
            $history = $governor->requestCountsManager->countsByUsernameBetween($username, $limits['From'], $limits['Until']);
            $this->addHistoryTableParams($params, $history, 'ipAddress', 'Adres');
        }

        // #TODO: make params testable
        return $this->render(
            $this->container->getParameter('metaclass_auth_guard.statistics.template'),
            $params);
    }

    protected function addHistoryTableParams(&$params, $history, $col1Field, $col1Label)
    {
        $params['columnSpec'] = array(
            'Vanaf' => 'dtFrom',
            $col1Label => $col1Field,
            'Succesvol' => 'loginsSucceeded',
            'Mislukt' => 'loginsFailed',
            'adres' => 'ipAddressBlocked',
            'naam' => 'usernameBlocked',
            'naam op adres' => 'usernameBlockedForIpAddress',
            'naam op cookie' => 'usernameBlockedForCookie',
        );
        forEach($history as $key => $row) {
            $dt = new \DateTime($row['dtFrom']);
            $history[$key]['dtFrom'] = $this->dtTransformer->transform($dt);
        }
        $params['items'] =  $history;
        $params['blockedHeaderIndent'] = 5;
    }

    protected function addStatsPeriodForm(&$params, $governor, $label, $limitFrom=null)
    {
        $limits['Until'] = new \DateTime();
        $labels = array('From' => 'Van', 'Until' => 'Tot');
        $historyLimit = new \DateTime("$governor->dtString - $governor->keepCountsFor");
        $form = $this->createForm(
            new StatsPeriodType($labels, $historyLimit, $this->dateTimeFormat),
            null,
            array('label' => $label, 'csrf_protection' => false,));
        if ($limitFrom === null) {
            $form->submit($this->getRequest());
            if ($form->isValid()) {
                $limits['From'] = $form->get('From')->getData();
                $limits['Until'] = $form->get('Until')->getData();
            }
        } else {
            $limits['From'] = $limitFrom;
            $form->get('From')->setData($limitFrom);
            $form->get('Until')->setData($limits['Until']);
        }
        $params['form'] = $form->createView();
        return $limits;
    }

    protected function addStatisticCommonParams(&$params, $governor)
    {
        $params['title'] = 'Inlogbeveiliging';
        $this->buildMenu($params, 'Guard_show');
        $fieldSpec = array(
            'Telt sinds' => 'countingSince',
            'Blokkeeer gebruikersnamen voor' => 'blockUsernamesFor',
            'Blokkeeer IP adressen voor' => 'blockIpAddressesFor',
            'Succesvolle inlogpogingen' => 'successCount',
            'Mislukte inlogpogingen' => 'failureCount',
        );
        $params['fieldSpec'] = isSet($params['fieldSpec'])
            ? array_merge($params['fieldSpec'], $fieldSpec)
            : $fieldSpec;

        $fieldValues['blockIpAddressesFor'] = $this->translatePeriod($governor->blockIpAddressesFor);
        $fieldValues['blockUsernamesFor'] = $this->translatePeriod($governor->blockUsernamesFor);
        $params['fieldValues'] = $fieldValues;
    }

    protected function addCountsGroupedTableParams(&$params, $governor, $limits)
    {
        $countsByIpAddress = $governor->requestCountsManager->countsGroupedByIpAddress($limits['From'], $limits['Until']);
        $params['columnSpec'] = array(
            'Adres' => 'ipAddress',
            'Blok' => 'blocked',
            'Namen' => 'usernames',
            'Succesvol' => 'loginsSucceeded',
            'Mislukt' => 'loginsFailed',
            'adres' => 'ipAddressBlocked',
            'naam' => 'usernameBlocked',
            'naam op adres' => 'usernameBlockedForIpAddress',
            'naam op cookie' => 'usernameBlockedForCookie',
        );
        if ($this->getRequest()->isMethod('POST')) {
            unSet($params['columnSpec']['Blok']);
        }
        forEach($countsByIpAddress as $key => $row)
        {
            $blocked = $row['loginsFailed'] >= $governor->limitBasePerIpAddress;
            $countsByIpAddress[$key]['blocked'] = $this->booleanLabels[$blocked];
            //nog toe te voegen: aantal gebruikernamen gereleased, aantal gebruikersnamen geblokkeerd

        }
        $params['items'] =  $countsByIpAddress;
    }

    protected function translatePeriod($durationString)
    {
        return str_replace(
            array('minutes', 'hours', 'days'),
            array('minuten', 'uren', 'dagen'),
            $durationString);
    }

    protected function getDecisionLabel($rejection)
    {
        if (!$rejection) {
            return '';
        }
        $fqClass = get_class($rejection);
        $pos = strRpos($fqClass, '\\');

        return $this->rejectionLabels[subStr($fqClass, $pos + 1)];
    }


    protected function buildMenu(&$params, $currentRoute)
    {
        // To be overridden by subclass
    }

} 