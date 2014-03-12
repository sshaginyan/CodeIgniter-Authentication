<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Authentication_Model extends CI_Model {
    
    private $users_table;
    private $login_attempts_table;
    private $expire_period;

    public function __construct() {
        parent::__construct();
        $this->load->database();
        $this->load->config('Authentication_Configuration');
        $this->users_table = $this->config->item('users_table');
        $this->login_attempts_table = $this->config->item('login_attempts_table');
        $this->expire_period = $this->config->item('expire_period');
    }
    
    public function register(array $data) {
        $this->db->insert($this->users_table, $data);
        return $this->db->insert_id();
    }

    public function activate_account($id, $activation_code) {
        $query = $this->db->get_where($this->users_table, array('id' => $id, 'activation_code' => $activation_code));

        if($query->num_rows() == 1) {
            $this->db->where('id', $id)->update($this->users_table, array('active' => TRUE, 'activation_code' => NULL));
            return TRUE;
        }

        return FALSE;

    }

    public function delete_user($email) {
        $this->db->delete($this->users_table, array('email' => $email));
        return $this->db->affected_rows() == 1;
    }

    public function update_remember_code($id, $salt) {
        $this->db->update($this->users_table, array('remember_code' => $salt), array('id' => $id));
        return $this->db->affected_rows() > -1;
    }

    public function increase_login_attempts($email, $ip_address) {
        return $this->db->insert($this->login_attempts_table, array('ip_address' => $ip_address, 'login' => $email, 'time' => time()));
    }

    public function clear_login_attempts($email, $ip_address) {
        return $this->db->where(array('ip_address' => $ip_address, 'login' => $email))->or_where('time <', time() - $this->expire_period, FALSE)->delete($this->login_attempts_table);
    }

    public function get_last_attempt_time($ip_address) {
        return $this->db->select_max('time')->get_where($this->login_attempts_table, array('ip_address' => $ip_address))->row();
    }

    public function login_attempts_count($ip_address) {
        return $this->db->get_where($this->login_attempts_table, array('ip_address' => $ip_address))->num_rows();
    }

    public function get_user($email) {

        $query = $this->db->get_where($this->users_table, array('email' => $email), 1);

        if($query->num_rows() == 1) {
            return $query->row();
        }

        return FALSE;
    }

    public function update_last_login($id) {
        $this->db->update($this->users_table, array('last_login' => time()), array('id' => $id));
        return $this->db->affected_rows() == 1;
    }

    public function is_email_taken($email) {
        return $this->db->where('email', $email)->count_all_results($this->users_table) > 0;
    }

    public function getTableFields() {
        return $this->db->list_fields($this->users_table);
    }

    public function update_user($id, $data) {
        return $this->db->update($this->users_table, $data, array('id' => $id));
    }

}