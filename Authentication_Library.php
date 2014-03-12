<?php  if(!defined('BASEPATH')) exit('No direct script access allowed');

class Authentication_Library {

    private $maximum_login_attempts;
    private $lockout_time;
    private $ip_address;
    private $user_expiration;

    public function __construct() {
        $this->load->helper('email');
        $this->load->helper('cookie');
        $this->load->library('session');
        $this->load->model('Authentication_Model');
        $this->load->config('Authentication_Configuration');
        $this->maximum_login_attempts = $this->config->item('maximum_login_attempts');
        $this->lockout_time = $this->config->item('lockout_time');
        $this->ip_address = $this->input->ip_address();
        $this->user_expiration = $this->config->item('user_expiration');
    }
    
    public function __get($var) {
		return get_instance()->$var;
	}

    public function register($email = '', $password = '', array $additional_information) {

        if(empty($email)) {
            return ERROR_EMAIL_EMPTY;
        }

        if(empty($password)) {
            return ERROR_PASSWORD_EMPTY;
        }

        if(!is_string($email)) {
            return ERROR_EMAIL_TYPE;
        }

        if(!is_string($password)) {
            return ERROR_PASSWORD_TYPE;
        }

        if (!valid_email($email)) {
            return ERROR_EMAIL_FORMAT_INVALID;
        }

        if(!checkdnsrr(explode('@', $email)[1], 'MX')) {
            return ERROR_EMAIL_DOMAIN_UNAVAILABLE;
        }

        if($this->M_Authentication->is_email_taken($email)) {
            return ERROR_EMAIL_TAKEN;
        }

        $data = array(
            'email' => $email,
            'password' => password_hash($password, PASSWORD_BCRYPT),
            'ip_address' => $this->ip_address,
            'created_on' => time(),
            'last_login' => time(),
            'active' => FALSE,
            'activation_code' => sha1(md5(microtime()))
        );

        $this->data_sanitization($additional_information);

        $data = array_merge($additional_information, $data);

        $id = $this->M_Authentication->register($data);

        $subject = 'Activate Your Account';
        $message = 'Hello, click this link to activate your account ';
        $message .= anchor('welcome/activation/'.$id.'/'.$data['activation_code']);
        send_email($email, $subject, $message);

    }

    public function activate_account($id = '', $activation_code = '') {

        if(!is_string($id)) {
            return ERROR_ID_TYPE;
        }

        if(empty($id)) {
            return ERROR_ID_EMPTY;
        }

        if(!is_string($activation_code)) {
            return ERROR_ACTIVATION_CODE_TYPE;
        }

        if(empty($activation_code)) {
            return ERROR_ACTIVATION_CODE_EMPTY;
        }

        $this->M_Authentication->activate_account($id, $activation_code);
    }

    public function login($email = '', $password = '', $remember = FALSE) {
        if(empty($email)) {
            return ERROR_EMAIL_EMPTY;
        }

        if(empty($password)) {
            return ERROR_PASSWORD_EMPTY;
        }

        if(!is_string($email)) {
            return ERROR_EMAIL_TYPE;
        }

        if(!is_string($password)) {
            return ERROR_PASSWORD_TYPE;
        }

        if($this->is_account_time_locked()) {
            return ERROR_ACCOUNT_TIME_LOCKED;
        }

        $user = $this->M_Authentication->get_user($email);

        if($user && password_verify($password, $user->password)) {

            if($user->active == 0) {
                return ERROR_USER_INACTIVE;
            }

            $this->set_session($user);
            $this->M_Authentication->update_last_login($user->id);
            $this->M_Authentication->clear_login_attempts($email, $this->ip_address);

            if ($remember){
                $this->remember_user($user);
            }

            return TRUE;

        }
        $this->M_Authentication->increase_login_attempts($email, $this->ip_address);

        return ERROR_LOGIN_REJECTED;

    }

    public function update_user($email = '', array $data) {

        if(empty($email)) {
            return ERROR_EMAIL_EMPTY;
        }

        if(!is_string($email)) {
            return ERROR_EMAIL_TYPE;
        }

        $user = $this->M_Authentication->get_user($email);

        if(array_key_exists($email, $data) && $this->M_Authentication->is_email_taken($email) && $user->email !== $data[$email]) {
            return FALSE;
        }


        $this->data_sanitization($data);

        if(array_key_exists('password', $data) || array_key_exists('email', $data)) {
            if(array_key_exists('password', $data)) {
                if(!empty($data['password'])) {
                    $data['password'] = password_hash($data['password'], PASSWORD_BCRYPT);
                } else {
                    unset($data['password']);
                }
            }
        }

        $this->M_Authentication->update_user($user->id, $data);

        return TRUE;
    }

    public function delete_user($email = '') {

        if(empty($email)) {
            return ERROR_EMAIL_EMPTY;
        }

        if(!is_string($email)) {
            return ERROR_EMAIL_TYPE;
        }


        if($this->M_Authentication->delete_user($email)) {
            return TRUE;
        }

        return FALSE;

    }

    public function logged_in() {
        return (bool) $this->session->userdata('email');
    }

    public function logout() {

        $this->session->unset_userdata(array('id' => '', 'user_id' => '', 'email' => ''));

        if (get_cookie('identity')) {
            delete_cookie('identity');
        }

        if (get_cookie('remember_code')) {
            delete_cookie('remember_code');
        }

        $this->session->sess_destroy();
        $this->session->sess_create();

        return TRUE;
    }

    private function remember_user($user) {

        $salt = sha1($user->password);

        if($this->M_Authentication->update_remember_code($user->id, $salt)) {

            set_cookie(array(
                'name' => 'identity',
                'value' => $user->email,
                'expire' => $this->user_expiration
            ));

            set_cookie(array(
                'name' => 'remember_code',
                'value' => $salt,
                'expire' => $this->user_expiration
            ));

            return TRUE;
        }

        return FALSE;

    }

    private function set_session($user) {
        $session_data = array('id' => $user->id, 'email' => $user->email, 'last_login' => $user->last_login);
        $this->session->set_userdata($session_data);
    }

    private function is_account_time_locked() {
        if($this->maximum_login_attempts > 0) {
            $attempts_count = $this->M_Authentication->login_attempts_count($this->ip_address);
            return $attempts_count >= $this->maximum_login_attempts &&
            $this->M_Authentication->get_last_attempt_time($this->ip_address)->time > (time() - $this->lockout_time);
        }

        return FALSE;
    }

    private function data_sanitization(array &$additional_information) {

        $field_names = $this->M_Authentication->getTableFields();

        foreach(array_keys($additional_information) as $key) {
            if(!in_array($key, $field_names)) {
                unset($additional_information[$key]);
            }
        }

    }

}