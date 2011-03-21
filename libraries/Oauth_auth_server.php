<?php
error_reporting(-1);
ini_set('display_errors', '1');

/**
 * OAuth 2.0 authorization server (draft 13 spec)
 *
 * @package             CodeIgniter
 * @author              Alex Bilbie | www.alexbilbie.com | alex@alexbilbie.com
 * @copyright   		Copyright (c) 2010, Alex Bilbie.
 * @license             http://codeigniter.com/user_guide/license.html
 * @link                http://alexbilbie.com
 * @version             Version 0.1
 *
 * Remember to edit validate_user() to meet fit your existing application!
 */

class Oauth_auth_server {

	protected $CI;

	function __construct()
	{
		$this->CI =& get_instance();
	}
	
	/**
	 * Ensures GET parameters exist
	 * 
	 * @access public
	 * @param array $params
	 * @return bool|array
	 */
	public function validate_params($params = array())
	{
		if (count($params) > 0)
		{
			$vars = array();
			foreach ($params as $param => $options)
			{
				$i = trim($this->CI->input->get($param, TRUE));
				
				if (($i === FALSE || $i == "") && $options !== FALSE)
				{
					$this->param_error = "Missing or empty parameter `{$param}`";
					return FALSE;
				}
				
				if (is_array($options))
				{
					if (in_array($i, $options) == FALSE)
					{
						$this->param_error = "`{$param}` should be equal to: '" . implode("' or '", $options) . "'";
						return FALSE;
					}
				}
				
				$vars[$param] = trim($i);
			}
			
			return $vars;
		}
	}
	
	
	/**
	 * Validates a client's credentials
	 * 
	 * @access public
	 * @param string $client_id
	 * @param mixed $client_secret
	 * @param mixed $redirect_uri
	 * @return bool|object
	 */
	function validate_client($client_id = "", $client_secret = NULL, $redirect_uri = NULL)
	{
		$params = array(
			'client_id' => $client_id,
		);
		
		if ($client_secret !== NULL)
		{
			$params['client_secret'] = $client_secret;
		}
		
		if ($redirect_uri !== NULL)
		{
			$params['redirect_uri'] = $redirect_uri;
		}
	
		$client_check_query = $this->CI->db->select(array('name', 'client_id', 'auto_approve'))->get_where('applications', $params);
						
		if ($client_check_query->num_rows() > 0)
		{
			return $client_check_query->row();
		}
		
		else
		{
			return FALSE;
		}
	}
	
	
	/**
	 * Generates a new authorise code once a user has approved an application
	 * 
	 * @access public
	 * @param mixed $client_id
	 * @param mixed $user_id
	 * @param mixed $redirect_uri
	 * @param array $scopes
	 * @return string
	 */
	function new_auth_code($client_id = '', $user_id = '', $redirect_uri = '', $scopes = array())
	{
		// Check if the user has an access_code already
		$token_exists = $this->CI->db->select('access_token')->where(array('user_id' => $user_id, 'client_id' => $client_id))->count_all_results('oauth_sessions');
		
		// Update an existing session with the new code
		if ($token_exists == 1)
		{
			$code = md5(time().uniqid());
			
			$this->CI->db->where(array('user_id' => $user_id, 'client_id'=>$client_id))->update('oauth_sessions', array('code' => $code, 'access_token' => NULL, 'stage' => 'request', 'last_updated' => time()));
		}
		
		// Create a new oauth session
		else
		{
			$code = md5(time().uniqid());
			
			$this->CI->db->insert('oauth_sessions', array('client_id' => $client_id, 'redirect_uri' => $redirect_uri, 'user_id' => $user_id, 'code' => $code, 'first_requested' => time(), 'last_updated' => time()));
			$insert_id = $this->CI->db->insert_id();
			
			// Add the scopes
			if (count($scopes) > 0)
			{
				foreach ($scopes as $scope)
				{
					$scope = trim($scope);
					
					if(trim($scope) !== "")
					{
						$this->CI->db->insert('oauth_session_scopes', array('session_id' => $insert_id, 'scope'=>$scope));
					}
				}
			}
		}
		
		return $code;
	}
	
	
	/**
	 * validate_auth_code function.
	 * 
	 * @access public
	 * @param string $code
	 * @param string $client_id
	 * @param string $redirect_uri
	 * @return bool|int
	 */
	function validate_auth_code($code = "", $client_id = "", $redirect_uri = "")
	{
		$validate = $this->CI->db->select(array('id'))->get_where('oauth_sessions', array('client_id' => $client_id, 'redirect_uri' => $redirect_uri, 'code' => $code));
		
		if ($validate->num_rows() == 0)
		{
			return FALSE;
		}
		
		else
		{
			$result = $validate->row();
			return $result->id;
		}
	}
	
	
	/**
	 * Generates a new access token (or returns an existing one)
	 * 
	 * @access public
	 * @param string $session_id. (default: '')
	 * @return string
	 */
	function get_access_token($session_id = '')
	{
		// Check if an access token exists already
		$exists_query = $this->CI->db->select('access_token')->get_where('oauth_sessions', array('id' => $session_id, 'access_token !=' => NULL));
		
		// If an access token already exists, return it and remove the authorization code
		if ($exists_query->num_rows() == 1)
		{
			// Remove the authorization code
			$this->CI->db->where(array('id' => $session_id))->update('oauth_sessions', array('code'=>NULL));
			
			// Return the access token
			$exists = $exists_query->row();
			return $exists->access_token;
		}
		
		// An access token doesn't exist yet so create one and remove the authorization code
		else
		{
			$access_token = time().'|'.md5(uniqid());
			
			$updates = array(
				'code' => NULL,
				'access_token' => $access_token,
				'last_updated' => time(),
				'stage' => 'granted'
			);
			
			// Update the OAuth session
			$this->CI->db->where(array('session_id' => $session_id))->update('oauth_sessions', $updates);
			
			// Update the session scopes with the access token
			$this->CI->db->where(array('session_id' => $session_id))->update('oauth_session_scopes', array('access_token' => $access_token));
						
			return $access_token;
		}
	}
	
	function new_access_token()
	{
		
	}
	
	
	/**
	 * Tests if a user has already authorized an application and an access token has been granted
	 * 
	 * @access public
	 * @param string $user_id
	 * @param string $client_id
	 * @return bool
	 */
	function access_token_exists($user_id = '', $client_id = '')
	{
		$token_query = $this->CI->db->select('access_token')->get_where('oauth_sessions', array('client_id' => $client_id, 'user_id'=>$user_id, 'access_token !=' => NULL));
		
		if ($token_query->num_rows() == 1)
		{
			return TRUE;
		}
		
		else
		{
			return FALSE;
		}
	}
	
	
	/**
	 * Validates an access token
	 * 
	 * @access public
	 * @param string $access_token. (default: "")
	 * @param array $scope. (default: array())
	 * @return void
	 */
	function validate_access_token($access_token = '', $scopes = array())
	{
		// Validate the token exists
		$valid_token = $this->CI->db->where(array('access_token' => $access_token))->count_all_results('oauth_session');
		
		// The access token doesn't exists
		if ($valid_token == 0)
		{
			return FALSE;
		}

		// The access token does exist, validate each scope
		else
		{
			if (count($scopes) > 0)
			{
				foreach ($scopes as $scope)
				{
					$scope_exists = $this->CI->db->where(array('access_token' => $access_token, 'scope' => $scope))->count_all_results('oauth_session_scopes');
					
					if ($scope_exists == 0)
					{
						return FALSE;
					}
				}
				return TRUE;
			}
			
			else
			{
				return TRUE;
			}
		}
		
	}
	
	
	/**
	 * Generates the redirect uri with appended params
	 * 
	 * @access public
	 * @param string $redirect_uri. (default: "")
	 * @param array $params. (default: array())
	 * @return string
	 */
	function redirect_uri($redirect_uri = '', $params = array(), $query_delimeter = '?')
	{
		if (strstr($redirect_uri, $query_delimeter))
		{
			$redirect_uri = $redirect_uri . implode('&', $params);
		}
		else
		{
			$redirect_uri = $redirect_uri . $query_delimeter . implode('&', $params);
		}
		
		return $redirect_uri;
	}
	
		
	/**
	 * Sign the user into your application.
	 *
	 * Edit this function to suit your needs. It must return a user's id as a string
	 * or FALSE if the sign in was incorrect
	 * 
	 * @access public
	 * @return string|bool
	 */
	function validate_user($username = "", $password = "")
	{
		$password = md5($password);
		
		$user_test = $this->CI->db->get_where('users', array('username'=>$username, 'password'=>$password));
		
		if ($user_test->num_rows() == 0)
		{
			return FALSE;
		}
		
		else
		{
			$result = $user_test->row();
			return $result->id;
		}
	}
		
}