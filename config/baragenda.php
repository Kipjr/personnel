<?php

return [

    'contact' => [
        'bar' => env('BARAGENDA_BAR_PHONE', ''),
        'mail' => env('BARAGENDA_CONTACT_MAIL', ''),
        'printer' => env('BARAGENDA_PRINTER_MAIL', ''),
    ],


    'ldap' => [
        'admin_group' => env('BARAGENDA_LDAP_ADMIN_GROUP'),
        'allowed_group' => env('BARAGENDA_LDAP_ALLOWED_GROUP'),
        'user_base' => env('BARAGENDA_LDAP_USER_BASEDN'),
    ],

    'url' => [
        'forgot_password' => env('BARAGENDA_URL_FORGOT_PASSWORD'),
    ],

    'service_users' => [
        'users' => [
            [
                'lidnummer' => 'bar_soos',
                'name' => 'Bar soos',
                'token' => env('BARAGENDA_ACCOUNTURL_BAR001'),
            ],
            [
                'lidnummer' => 'bar_fz',
                'name' => 'Bar filmzaal',
                'token' => env('BARAGENDA_ACCOUNTURL_BAR002'),
            ]
        ],
        'whitelisted_ips' => explode(',', env('BARAGENDA_ACCOUNT_WHITELIST_IPS')),
    ],
    'google' => [
        'calendar' => [
            'public' =>  env('GOOGLE_CALENDAR_ID_PUBLIC'),                
            'public_name' =>  env('GSUITE_CAL_PUBL_SUMM_DISPLAY'),                
            'private' =>  env('GOOGLE_CALENDAR_ID_PRIVATE'),                 
            'private_name' =>  env('GSUITE_CAL_PRIV_SUMM_DISPLAY')                 
        ]        
    ]

];