# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  # response(body: event, status: 200)

  httpMethod = event["httpMethod"]
  path = event["path"]

  if httpMethod == 'POST'
    if path == '/auth/token'
      post_auth_token(event)
    else
      response(status: 404)
    end
  elsif httpMethod == 'GET'
    if path == '/'
      get_root(event)
    else
      response(status: 404)
    end
  else
    response(status: 405)
  end
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    headers: {'Content-Type' => 'application/json' },
    statusCode: status
  }
end

def post_auth_token(event)
  headers = event['headers']
  if header["Content-Type"] !='application/json'
    return response(status: 415)
  end

  begin
    data = JSON.parse(event['body'])
  rescue JSON::ParserError
    return response(status: 422)
  end

  cotent = {
    'data' => data,
    'exp' => Time.now.to_i + 5,
    'nbf' => Time.now.to_i + 2
  }

  token = JWT.encode(cotent, ENV['JWT_SECRET'], 'HS256')
  response(body: { 'token' => token }, status: 201)

end

def get_root(event)
  headers = event['headers']
  if headers['Authorization'][0..6]!='Bearer '
    return response(status: 403)
  end

  token =  headers['Authorization'].split(' ').last
  begin
    decoded_token = JWT.decode(token, ENV['JWT_SECRET'], true, algorithm: 'HS256')[0]
    data = decoded_token['data']
    response(body: data, status: 200)
  rescue JWT::ExpiredSignature, JWT::ImmatureSignature
    response(status: 401)
  rescue JWT::DecodeError
    response(status: 403)
  end

end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
