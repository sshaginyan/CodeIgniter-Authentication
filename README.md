# CodeIgniter Authentication Library

This was tested on PHP version 5.5.10, MySQL version 14.14, and Apache Tomcat version 2.2.26.
Put Authentication_Library.php in /application/libraries.
Put Authentication_Model.php in /application/models.
Put Authentication_Configuratino.php in /application/config.

#### $config['users_table']
The table name used to hold user information. [String]
#### $config['login_attempts_table']
The table name used to hold login attempts. [String]
#### $config['maximum_login_attempts']
Determines the maximum login attempts to lockout the user. [Int]
#### $config['lockout_time']
Determines the lockout time for a login in seconds. [Int]
#### $config['user_expiration']
The experation time for the remember_user option in seconds. [Int]

#### $this->Authentication_Library->register($email, $password, $additional_information);

#### $this->Authentication_Library->activate_account($id, $activation_code);

#### $this->Authentication_Library->login($email, $password, $remember);

#### $this->Authentication_Library->update_user($email, $updated_information);

#### $this->Authentication_Library->delete_user($email);

#### $this->Authentication_Library->logged_in();

#### $this->Authentication_Library->logout();
