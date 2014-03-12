<?php  if (!defined('BASEPATH')) exit('No direct script access allowed');

define('ERROR_EMAIL_TYPE', 0);
define('ERROR_PASSWORD_TYPE', 1);
define('ERROR_EMAIL_TAKEN', 2);
define('ERROR_EMAIL_FORMAT_INVALID', 3);
define('ERROR_EMAIL_DOMAIN_UNAVAILABLE', 4);
define('ERROR_EMAIL_EMPTY', 5);
define('ERROR_PASSWORD_EMPTY', 6);
define('ERROR_ID_TYPE', 7);
define('ERROR_ID_EMPTY', 8);
define('ERROR_ACTIVATION_CODE_TYPE', 9);
define('ERROR_ACTIVATION_CODE_EMPTY', 10);
define('ERROR_ACCOUNT_TIME_LOCKED', 11);
define('ERROR_LOGIN_REJECTED', 12);
define('ERROR_USER_INACTIVE', 13);

$config['users_table'] = 'users';
$config['login_attempts_table'] = 'login_attempts';

$config['email_verification'] = TRUE;
$config['username_suggestion'] = TRUE;
$config['maximum_login_attempts'] = 5;
$config['lockout_time'] = 5;
$config['expire_period'] = 5;
$config['user_expiration'] = 3600;