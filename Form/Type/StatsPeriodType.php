<?php

namespace Metaclass\AuthenticationGuardBundle\Form\Type;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\Date;
use Symfony\Component\Validator\Constraints\GreaterThan;

class StatsPeriodType extends AbstractType
{
    protected $labels;

    public function __construct($labels, \DateTime $min, $dateTimeFormat)
    {
        $this->labels = $labels;
        $this->min = $min;
        $this->dateTimeFormat = $dateTimeFormat;
    }

    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $constraints = array(new Date(),
            new GreaterThan(array('value' => $this->min)),
        );
        $builder->add('From', 'datetime', array(
                'label' => $this->labels['From'],
                'required' => true,
                'widget' => 'single_text',
                'format' => $this->dateTimeFormat,
                'constraints' => $constraints
            ));
        $builder->add('Until', 'datetime', array(
                'label' => $this->labels['Until'],
                'required' => false,
                'widget' => 'single_text',
                'format' => $this->dateTimeFormat,
                'constraints' => $constraints
            ));
    }

    public function getName()
    {
        return 'StatsPeriod';
    }
}