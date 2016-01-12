<?php

namespace Metaclass\AuthenticationGuardBundle\Form\Type;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Validator\Constraints\Date;
use Symfony\Component\Validator\Constraints\GreaterThan;
use Symfony\Component\Form\Extension\Core\Type;


class StatsPeriodType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $constraints = array(new Date(),
            new GreaterThan(array('value' => $options['min'])),
        );
        $builder->add('From', Type\DateTimeType::class, array(
                'label' => $options['labels']['From'],
                'required' => true,
                'widget' => 'single_text',
                'date_format' => $options['date_format'],
                'format' => $options['dateTimePattern'],
                'constraints' => $constraints
            ));
        $builder->add('Until', Type\DateTimeType::class, array(
                'label' => $options['labels']['Until'],
                'required' => false,
                'widget' => 'single_text',
                'date_format' => $options['date_format'],
                'format' => $options['dateTimePattern'],
                'constraints' => $constraints
            ));
    }

    public function getBlockPrefix()
    {
        return 'StatsPeriod';
    }
}