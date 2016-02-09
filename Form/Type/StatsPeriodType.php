<?php

namespace Metaclass\AuthenticationGuardBundle\Form\Type;

use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
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
        $builder->add('From', 'Symfony\Component\Form\Extension\Core\Type\DateTimeType', array(
                'label' => $options['labels']['From'],
                'required' => true,
                'widget' => 'single_text',
                'date_format' => $options['date_format'],
                'format' => $options['dateTimePattern'],
                'constraints' => $constraints
            ));
        $builder->add('Until', 'Symfony\Component\Form\Extension\Core\Type\DateTimeType', array(
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

    public function configureOptions(OptionsResolver $resolver)
    {
        $resolver->setDefaults(array('dateTimePattern' => null, 'date_format' => Type\DateTimeType::DEFAULT_DATE_FORMAT));
        $resolver->setRequired(array('min', 'labels', 'date_format', 'dateTimePattern'));
    }
}