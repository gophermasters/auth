#!/usr/bin/env perl

use JSON;
use Crypt::JWT qw(decode_jwt encode_jwt);
use Data::Dumper;
use Try::Catch;
use Dancer2;


# set serializer => 'XML';
set serializer => 'JSON'; 
set port => 3000;
set content_type => 'application/json';

# Request handling

# hook before => sub {
#     if (!session('user')  request->path !~ m{^/login}) {
#         forward '/login', { requested_path => request->path };
#     }
# };


get '/' => sub{
    return {message => "Perl REST API with Dancer using JWT Auth "};
};

# params->{name};
# query_parameters->get('user')
# body_parameters->get('user')

post '/accessToken' => sub {

    # print Dumper request;

    # Verify Content-Type
    return sendErrResponse('Content-Type') if ! validateHeader(request,'Content-Type');

    # Validate user
    my $username = body_parameters->get('username');
    my $password = body_parameters->get('password');
    my $received_token = validateHeader(request,'Authorization');

    if ($username ne '' && $password ne ''){

        # Verify user/pass here - to be done with SQL (DBI module)
        if (lc($username) eq 'dwight'&& $password eq 'bearsbeets'){

            # Send token info
            my %token_details = createToken($username);
            return \%token_details;

        }

        return {message => "Request failed", error=>"Unable to validate user"};

    }
    elsif ($received_token){

        my $username = validateToken($received_token,'refresh');
        
        if  ($username){

            my %token_details = createToken($username);
            return \%token_details;

        }

        return {message => "Request failed", error=>"Invalid/Expired refresh token."};

    }

    return {message => "Request failed", error=>"Missing username/password properties"};

};

get '/users' => sub{

    # Verify Content-Type
    return sendErrResponse('Content-Type') if ! validateHeader(request,'Content-Type');

    # Verify token received
    my $received_token = validateHeader(request,'Authorization');
    return sendErrResponse('Authorization') if ! $received_token;

    # Validate token/user
    my $username = validateToken($received_token,'access') || return sendErrResponse('expiredToken');

    # Handle Request

    my %users = (
        RegionalManager => {
            id   => "1",
            name => "M.Scott",
        },
        NumberTwo => {
            id   => "2",
            name => "J.Halpert",
        },
        BeetFarmer => {
            id   => "3",
            name => "D.Schrute",
        },
        You => {
            id => 100,
            name => $username
        }
    );

    return \%users;

};

get '/Accounts/:accountid' => sub{

    # Verify Content-Type
    return sendErrResponse('Content-Type') if ! validateHeader(request,'Content-Type');

    # Verify token received
    my $received_token = validateHeader(request,'Authorization');
    return sendErrResponse('Authorization') if ! $received_token;

    # Validate access token/user
    my $username = validateToken($received_token,'access') || return sendErrResponse('expiredToken');
    
    # Handle Request - /Accounts/:accountid
    my $req_accountid = params->{accountid};
    
    my $accounts_json = qq(
        {
            "accountId": "$req_accountid",
            "username": "$username"
        }
    );

    return from_json($accounts_json);

};

# get '/users/:name' => sub {
#     my $user = params->{name};
#     return {message => "Hello $user"};
# };


# Token subs
sub validateToken
{
    my $sub_token = $_[0];
    my $sub_token_type = $_[1];

    my $access_key = 'accessSecret';
    my $refresh_key = 'refreshSecret';

    my $secret_key = $sub_token_type eq 'access' ? $access_key : $refresh_key; 

    try {
        my $payload = decode_jwt(token=>$sub_token, key=>$secret_key, verify_exp=>1);

        return 0 if ( $payload->{expiry} <= time);
        
        return $payload->{data};


    }
    catch{ return 0; }

}

sub createToken
{
    my $sub_payload = $_[0];

    my $access_key = 'accessSecret';
    my $refresh_key = 'refreshSecret';

    my $access_token_rel_expiry = 30; # 30s
    my $access_token_expiry = time + $access_token_rel_expiry;
 
    my $refresh_token_rel_expiry = 600; # 10M
    my $refresh_token_expiry = time + $refresh_token_rel_expiry;

    my $access_token = encode_jwt(payload=>{data=>"$sub_payload", expiry=>$access_token_expiry}, key=>$access_key, alg=>'HS256', relative_exp=>$access_token_rel_expiry, is_refresh=> 0 );
    my $refresh_token = encode_jwt(payload=>{data=>"$sub_payload", expiry=>$refresh_token_expiry}, key=>$refresh_key, alg=>'HS256', relative_exp=>$refresh_token_rel_expiry, is_refresh=> 1 );
    return ( accessToken => $access_token, accessTokenExpiry=> $access_token_expiry, refreshToken=>$refresh_token, refreshTokenExpiry=>$refresh_token_expiry);
}

sub validateHeader
{
    my $request = $_[0];
    my $header = $_[1];

    if ($header eq 'Authorization'){

        my $bearer_token = defined request->{env}->{HTTP_AUTHORIZATION} ? request->{env}->{HTTP_AUTHORIZATION} : ''; 
        $bearer_token =~ s/\s+Authorization\s//;
        $bearer_token = 'invalid' if $bearer_token eq '' || ( $bearer_token !~ m/Bearer/ );
        $bearer_token =~ s/\s?Bearer\s//;
        $bearer_token =~ s/\s+$//; # Right trim
        $bearer_token = 0 if $bearer_token eq 'invalid';
        return $bearer_token;

    }
    elsif ($header eq 'Content-Type'){

        my $content_type = defined request->{env}->{CONTENT_TYPE} ? request->{env}->{CONTENT_TYPE} : ''; 
        $content_type =~ s/\s//g;
        return lc($content_type) eq 'application/json' ? 1 : 0;
    }
}

sub sendErrResponse
{
    my $response_type = $_[0];

    return {message => "Request failed", error=> "Missing/Invalid 'Content-Type' Header. Expected 'application/json'"} if $response_type eq 'Content-Type';
    return {message => "Request failed", error=> "Missing/Invalid 'Authorization' Header"} if $response_type eq 'Authorization';
    return {message => "Request failed", error=> "Invalid/Expired Access Token."} if $response_type eq 'expiredToken';

}

dance;



#### GETTING PARAMS

# params->{name}; # This is path param - not query param
# query_parameters->get('user')
# body_parameters->get('user')



#### STRING TO JSON

# my $accounts_json = qq(
#     {
#         "accountId": "$req_accountid",
#         "accountName": "$req_accountid_name",
#         "accountOwnerName": "$accountid_owner_name"
#     }
# );

# return from_json($accounts_json);


#### HASH TO JSON

# $accounts_list_json->[$a] = {
#     id => $accounts_list->[$a][0],
#     accountName => $accounts_list->[$a][1],
#     accountOwner => $accountid_owner,
#     admins => $admin_count,
#     licenses => $lic_count,
#     alerts => $alerts_count,
#     resources =>from_json($resources_json)
# };

# my %return_json = ( results=>$accounts_list_json );


