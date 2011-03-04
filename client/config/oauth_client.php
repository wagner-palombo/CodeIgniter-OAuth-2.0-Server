<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

// Change these
$config['oauth_client_id'] = '';
$config['oauth_client_secret'] = '';
$config['oauth_scope'] = array('basic');
$config['oauth_redirect_uri'] = 'http://client-url.com/signin/redirect';
$config['oauth_signout_redirect_uri'] = 'http://client-url.com/';
$config['oauth_base'] = 'https://auth-server-url.com/oauth2/';

// Don't touch these
$config['oauth_signin_params'] = array('response_type=code', 'scope='.implode(',', $config['oauth_scope']), 'client_id='.$config['oauth_client_id'], 'redirect_uri='.$config['oauth_redirect_uri']);
$config['oauth_signin_url'] = $config['oauth_base'].'?'.implode('&', $config['oauth_signin_params']);

$config['oauth_signout_params'] = array('redirect_uri='.$config['oauth_signout_redirect_uri']);
$config['oauth_signout_url'] = $config['oauth_base'].'signout?'.implode('&', $config['oauth_signout_params']);

$config['oauth_access_token_params'] = array('grant_type=authorization_code', 'client_id='.$config['oauth_client_id'], 'client_secret='.$config['oauth_client_secret'], 'redirect_uri='.$config['oauth_redirect_uri']);
$config['oauth_access_token_uri'] = $config['oauth_base'].'access_token?'.implode('&', $config['oauth_access_token_params']).'&code=';