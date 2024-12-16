#!/bin/bash

# Generate salt
SALT=$(openssl rand -hex 16)

# Create the PHP script with exact same format
php -r "
\$salt = '${SALT}';
\$admin_username = getenv('ADMIN_USERNAME');
\$admin_password = getenv('ADMIN_PASSWORD');
\$admin_id = hash('sha256', \$admin_username . \$salt);
\$tester_id = hash('sha256', 'tester' . \$salt);
\$data = [
    \$admin_id => [
        'id' => \$admin_id,
        'username' => \$admin_username,
        'password' => \$admin_password,
        'role' => 'admin',
        'signature' => ''
    ],
    \$tester_id => [
        'id' => \$tester_id,
        'username' => 'tester',
        'password' => 'test123',
        'role' => 'agent',
        'signature' => ''
    ]
];
file_put_contents('/var/www/html/user_data.json', json_encode(\$data));
"
cp /var/www/html/user_data.json /var/www/html/user_data_bak.json

echo "SALT=${SALT}" >> /var/www/html/.env
