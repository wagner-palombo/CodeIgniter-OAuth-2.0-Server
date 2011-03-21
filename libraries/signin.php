<?php

/**
 * OAuth 2.0 client for use with the included auth server
 * *
 * @package             CodeIgniter
 * @author              Alex Bilbie | www.alexbilbie.com | alex@alexbilbie.com
 * @copyright   		Copyright (c) 2010, Alex Bilbie.
 * @license             http://codeigniter.com/user_guide/license.html
 * @link                http://alexbilbie.com
 * @version             Version 0.1
 */


class Signin extends CI_Controller {
	
	function __construct()
	{
		parent::__construct();
	}
		
	function index()
	{
		$this->load->library('oauth_client');
		$this->oauth_client->sign_in();
	}
	
	function signout()
	{
		$this->load->library('oauth_client');
		$this->session->sess_destroy();
		$this->oauth_client->sign_out();
	}
	
	function redirect()
	{
		$this->load->library('oauth_client');
		
		if ($this->input->get('error'))
		{
			show_error('[OAuth error] '.$this->input->get('error'), 500);
		}
						
		elseif ($this->input->get('code'))
		{
			$code = $this->input->get('code');
			$access_token = $this->oauth_client->get_access_token($code);
			
			if ($access_token)
			{
				// Check to see a user already exists in your app's database based by searching for the access token
				$user_exists = $this->session->access_token_exists($access_token);
				
				if ($user_exists)
				{
					// The user exists already, set up their sessions and redirect them to the app
				}
				
				else
				{
					// Get the user's details from the resource server using the access token
					
					// Insert the user's details into your app's database (remember to store the access token!)
					
					// Set up their sessions and redirect them to the app
				}
			}
			
			else
			{
				show_error($this->oauth_client->error, 500);
			}
		
		}
		
		else
		{
			// No authorise code or error code redirect them for trying to be a fool
			$this->load->helper('url');
			redirect(site_url() . 'signin');
		}
	}

} // EOF